#![cfg(target_arch = "aarch64")]

use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
    types::{ArgType, TypedArg},
};

const OVERFLOW: u64 = u64::MAX;
const BADARITH: u64 = u64::MAX - 1;

fn small(term: u64) -> Option<i64> {
    ((term & 15) == 15).then_some((term as i64) >> 4)
}

fn tagged(value: i64) -> Option<u64> {
    (-(1_i64 << 59)..=(1_i64 << 59) - 1)
        .contains(&value)
        .then_some(((value as u64) << 4) | 15)
}

/// Reference model of the arithmetic ops on smalls (OVERFLOW: the result is not a small,
/// which the emitted code hands to the erts runtime).
fn runtime_arith(op: u32, lhs: u64, rhs: u64) -> u64 {
    let Some(a) = small(lhs) else { return BADARITH };
    if op == 8 {
        return tagged(!a).unwrap_or(OVERFLOW);
    }
    if op == 9 {
        return a.checked_neg().and_then(tagged).unwrap_or(OVERFLOW);
    }
    let Some(b) = small(rhs) else { return BADARITH };
    if (op == 3 || op == 4) && b == 0 {
        return BADARITH;
    }
    if op == 10 || op == 11 {
        let left = (op == 10 && b >= 0) || (op == 11 && b < 0);
        let count = b.unsigned_abs();
        let shifted = if left {
            if a == 0 {
                0
            } else if count >= 64 {
                return OVERFLOW;
            } else {
                let wide = i128::from(a) * (1_i128 << count);
                let Ok(value) = i64::try_from(wide) else {
                    return OVERFLOW;
                };
                value
            }
        } else if count >= 64 {
            if a < 0 { -1 } else { 0 }
        } else {
            a >> count
        };
        return tagged(shifted).unwrap_or(OVERFLOW);
    }
    let result = match op {
        0 => a.checked_add(b),
        1 => a.checked_sub(b),
        2 => a.checked_mul(b),
        3 if b != 0 => Some(a / b),
        4 if b != 0 => Some(a % b),
        5 => Some(a & b),
        6 => Some(a | b),
        7 => Some(a ^ b),
        _ => None,
    };
    result.and_then(tagged).unwrap_or(OVERFLOW)
}

type BinaryRun = dyn Fn(u64, u64) -> u64;

/// An assembler with the process-wide fragments installed. The byte tests run only the inline
/// fast paths: the slow paths call the erts runtime (erl_arith.c), which needs the VM, and are
/// tested by the VM's arithmetic differentials.
fn new_asm() -> BeamModuleAssembler {
    use arinsal_beamasm::{raise_frag::RaiseFragments, yield_frag::YieldFragments};
    use std::sync::OnceLock;
    static YIELD: OnceLock<YieldFragments> = OnceLock::new();
    static RAISE: OnceLock<RaiseFragments> = OnceLock::new();
    extern "C" fn unused() {
        unreachable!("byte tests run only fast paths")
    }
    let raise = RAISE.get_or_init(|| {
        let context_switch = YIELD
            // No case collects: `garbage_collect` is never entered.
            .get_or_init(|| YieldFragments::new(unused as *const () as usize, 0).unwrap())
            .context_switch();
        RaiseFragments::new(
            unused as *const () as usize,
            unused as *const () as usize,
            context_switch,
        )
        .unwrap()
    });
    let mut asm = BeamModuleAssembler::new();
    asm.set_bif_fragments(raise.bif_fragments());
    asm
}

#[cfg(target_arch = "aarch64")]
fn run_binary(emit: impl FnOnce(&mut BeamModuleAssembler), lhs: u64, rhs: u64) -> u64 {
    let mut asm = new_asm();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
        .unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.ldr_post(Gpr::x(30), Gpr::sp(), 16)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(lhs);
    registers.x_reg_array[1] = arinsal_beamasm::rt::fixture_term(rhs);
    let mut stack = [0u64; 64];
    let stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    registers.x_reg_array[1].tagged_word()
}

#[cfg(target_arch = "aarch64")]
fn run_unary(emit: impl FnOnce(&mut BeamModuleAssembler), input: u64) -> u64 {
    let mut asm = new_asm();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
        .unwrap();
    emit(&mut asm);
    asm.emit_raw(|e| {
        e.ldr_post(Gpr::x(30), Gpr::sp(), 16)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(input);
    let mut stack = [0u64; 64];
    let stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    registers.x_reg_array[1].tagged_word()
}

#[cfg(target_arch = "aarch64")]
#[test]
fn integer_ops_on_smalls_use_the_inline_fast_paths() {
    let add = |a, b| {
        run_binary(
            |m| {
                m.emit_i_plus(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let sub = |a, b| {
        run_binary(
            |m| {
                m.emit_i_minus(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let mul = |a, b| {
        run_binary(
            |m| {
                m.emit_i_times(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let div = |a, b| {
        run_binary(
            |m| {
                m.emit_i_int_div(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let rem = |a, b| {
        run_binary(
            |m| {
                m.emit_i_rem(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let band = |a, b| {
        run_binary(
            |m| {
                m.emit_i_band(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let bor = |a, b| {
        run_binary(
            |m| {
                m.emit_i_bor(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let bxor = |a, b| {
        run_binary(
            |m| {
                m.emit_i_bxor(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let bsl = |a, b| {
        run_binary(
            |m| {
                m.emit_i_bsl(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let bsr = |a, b| {
        run_binary(
            |m| {
                m.emit_i_bsr(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::X(1), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            a,
            b,
        )
    };
    let cases = [
        (-3, 2),
        (0, -1),
        ((1 << 59) - 1, 1),
        (-(1 << 59), -1),
        (7, 0),
    ];
    for (a, b) in cases {
        let ta = tagged(a).unwrap();
        let tb = tagged(b).unwrap();
        let ops: [(u32, &BinaryRun); 10] = [
            (0, &add),
            (1, &sub),
            (2, &mul),
            (3, &div),
            (4, &rem),
            (5, &band),
            (6, &bor),
            (7, &bxor),
            (10, &bsl),
            (11, &bsr),
        ];
        for (op, run) in ops {
            let expected = runtime_arith(op, ta, tb);
            // A result that is not a small, a zero divisor, MIN_SMALL divided by -1 and a
            // negative shift count take the runtime slow path (erts_mixed_*, erts_int_div_rem,
            // erts_bsl/erts_bsr).
            let runtime = matches!(expected, OVERFLOW | BADARITH)
                || (matches!(op, 3 | 4) && (b == 0 || (a == -(1 << 59) && b == -1)))
                || (matches!(op, 10 | 11) && b < 0);
            if !runtime {
                assert_eq!(run(ta, tb), expected, "op {op} on {a}, {b}");
            }
        }
    }
    assert_eq!(
        run_unary(
            |m| m.emit_i_unary_minus(ArgVal::X(0), ArgVal::X(1)).unwrap(),
            tagged(7).unwrap()
        ),
        tagged(-7).unwrap()
    );
    assert_eq!(
        run_unary(
            |m| m.emit_i_bnot(ArgVal::X(0), ArgVal::X(1)).unwrap(),
            tagged(7).unwrap()
        ),
        tagged(!7).unwrap()
    );
    assert_eq!(
        run_unary(
            |m| m.emit_i_increment(ArgVal::X(0), 1, ArgVal::X(1)).unwrap(),
            tagged(7).unwrap()
        ),
        tagged(8).unwrap()
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn guard_arithmetic_emits_fail_label_handling() {
    let code_size = |with_fail_label| {
        let mut asm = new_asm();
        asm.emit_i_func_label(1).unwrap();
        asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
            .unwrap();
        if with_fail_label {
            asm.emit_i_plus_with_fail(
                TypedArg::new(ArgVal::X(0), ArgType::ANY),
                TypedArg::new(ArgVal::X(1), ArgType::ANY),
                ArgVal::X(1),
                2,
            )
            .unwrap();
        } else {
            asm.emit_i_plus(
                TypedArg::new(ArgVal::X(0), ArgType::ANY),
                TypedArg::new(ArgVal::X(1), ArgType::ANY),
                ArgVal::X(1),
            )
            .unwrap();
        }
        asm.return_().unwrap();
        asm.emit_label(2).unwrap();
        asm.return_().unwrap();
        let module = asm.finalize().unwrap();
        module.entries[&2] as usize - module.entries[&1] as usize
    };
    assert!(code_size(true) > code_size(false));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn immediate_add_sub_stay_on_the_small_fast_path() {
    let add = |lhs, immediate| {
        run_binary(
            |m| {
                m.emit_i_plus(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::Immediate(immediate), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            lhs,
            0,
        )
    };
    let sub = |lhs, immediate| {
        run_binary(
            |m| {
                m.emit_i_minus(
                    TypedArg::new(ArgVal::X(0), ArgType::ANY),
                    TypedArg::new(ArgVal::Immediate(immediate), ArgType::ANY),
                    ArgVal::X(1),
                )
                .unwrap()
            },
            lhs,
            0,
        )
    };
    let one = tagged(1).unwrap();
    assert_eq!(add(tagged(40).unwrap(), one), tagged(41).unwrap());
    assert_eq!(sub(tagged(40).unwrap(), one), tagged(39).unwrap());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn adjacent_y_registers_subtract_in_address_order() {
    let sub = |left: u32, right: u32, a: i64, b: i64| {
        let mut asm = new_asm();
        asm.emit_i_func_label(1).unwrap();
        asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
            .unwrap();
        asm.emit_i_minus(
            TypedArg::new(ArgVal::Y(left), ArgType::ANY),
            TypedArg::new(ArgVal::Y(right), ArgType::ANY),
            ArgVal::X(0),
        )
        .unwrap();
        asm.emit_raw(|e| {
            e.ldr_post(Gpr::x(30), Gpr::sp(), 16)?;
            e.mov_reg(Gpr::x(0), Gpr::xzr())?;
            e.ret(Gpr::x(30))
        })
        .unwrap();
        let module = asm.finalize().unwrap();
        let mut stack = [0u64; 8];
        stack[2] = tagged(a).unwrap();
        stack[3] = tagged(b).unwrap();
        let mut registers = SchedulerRegisters::default();
        let stop = stack.as_mut_ptr().wrapping_add(2);
        let mut header = ProcessHeader {
            stop,
            fcalls: 100,
            ..ProcessHeader::default()
        };
        let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
        assert_eq!(outcome, ExitReason::Returned);
        registers.x_reg_array[0].tagged_word()
    };
    assert_eq!(sub(0, 1, 10, 3), tagged(7).unwrap());
    assert_eq!(sub(1, 0, 10, 3), tagged(-7).unwrap());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn typed_power_of_two_multiply_and_mul_add_stay_on_the_fast_path() {
    let integer = |min, max| arinsal_beamasm::types::ArgType {
        union_bits: arinsal_beamasm::types::type_id::INTEGER,
        min: Some(min),
        max: Some(max),
        unit: 1,
    };
    let eight = tagged(8).unwrap();
    let mut asm = new_asm();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
        .unwrap();
    asm.emit_i_times(
        TypedArg::new(ArgVal::X(0), integer(0, 50)),
        TypedArg::new(ArgVal::Immediate(eight), ArgType::ANY),
        ArgVal::X(1),
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.ldr_post(Gpr::x(30), Gpr::sp(), 16)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged(5).unwrap());
    let mut stack = [0u64; 8];
    let stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    assert_eq!(registers.x_reg_array[1].tagged_word(), tagged(40).unwrap());

    let three = tagged(3).unwrap();
    let five = tagged(5).unwrap();
    let mut asm = new_asm();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_raw(|e| e.str_pre(Gpr::x(30), Gpr::sp(), -16))
        .unwrap();
    asm.emit_i_mul_add(
        TypedArg::new(ArgVal::X(0), integer(0, 20)),
        TypedArg::new(ArgVal::Immediate(three), ArgType::ANY),
        TypedArg::new(ArgVal::X(0), integer(0, 100)),
        TypedArg::new(ArgVal::Immediate(five), ArgType::ANY),
        ArgVal::X(1),
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.ldr_post(Gpr::x(30), Gpr::sp(), 16)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    registers.x_reg_array[0] = arinsal_beamasm::rt::fixture_term(tagged(4).unwrap());
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    assert_eq!(registers.x_reg_array[1].tagged_word(), tagged(17).unwrap());
}

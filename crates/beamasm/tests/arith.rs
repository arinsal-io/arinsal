use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    arith::ArithHelper,
    enter_native,
    module::{ArgVal, BeamModuleAssembler, FinalizedModule},
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

extern "C" fn runtime_arith(_process: *mut ProcessHeader, op: u32, lhs: u64, rhs: u64) -> u64 {
    if matches!(op, 16 | 17) {
        return lhs;
    }
    if op == 18 {
        return small(lhs).map_or(BADARITH, |value| (value as f64).to_bits());
    }
    if (19..=23).contains(&op) {
        let a = f64::from_bits(lhs);
        let b = f64::from_bits(rhs);
        let result = match op {
            19 => a + b,
            20 => a - b,
            21 => a * b,
            22 => a / b,
            _ => -a,
        };
        return if result.is_finite() {
            result.to_bits()
        } else {
            BADARITH
        };
    }
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

#[cfg(target_arch = "aarch64")]
fn run_binary(emit: impl FnOnce(&mut BeamModuleAssembler, ArithHelper), lhs: u64, rhs: u64) -> u64 {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm, runtime_arith);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module: FinalizedModule = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = lhs;
    registers.x_reg_array[1] = rhs;
    let mut stack = [0u64; 64];
    let stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    registers.x_reg_array[1]
}

#[cfg(target_arch = "aarch64")]
fn run_unary(emit: impl FnOnce(&mut BeamModuleAssembler, ArithHelper), input: u64) -> u64 {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit(&mut asm, runtime_arith);
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = input;
    let mut stack = [0u64; 64];
    let stop = stack.as_mut_ptr().wrapping_add(stack.len());
    let mut header = ProcessHeader {
        stop,
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let outcome = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    assert_eq!(outcome, ExitReason::Returned);
    registers.x_reg_array[1]
}

#[cfg(target_arch = "aarch64")]
#[test]
fn integer_ops_use_small_fast_paths_and_runtime_fallbacks() {
    let add = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_plus(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let sub = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_minus(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let mul = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_times(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let div = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_int_div(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let rem = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_rem(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let band = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_band(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let bor = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_bor(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let bxor = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_bxor(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let bsl = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_bsl(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap()
            },
            a,
            b,
        )
    };
    let bsr = |a, b| {
        run_binary(
            |m, h| {
                m.emit_i_bsr(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
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
        let expected = |op: u32| runtime_arith(std::ptr::null_mut(), op, ta, tb);
        assert_eq!(add(ta, tb), expected(0));
        assert_eq!(sub(ta, tb), expected(1));
        assert_eq!(mul(ta, tb), expected(2));
        assert_eq!(div(ta, tb), expected(3));
        assert_eq!(rem(ta, tb), expected(4));
        assert_eq!(band(ta, tb), expected(5));
        assert_eq!(bor(ta, tb), expected(6));
        assert_eq!(bxor(ta, tb), expected(7));
        assert_eq!(bsl(ta, tb), expected(10));
        assert_eq!(bsr(ta, tb), expected(11));
    }
    assert_eq!(add(tagged(2).unwrap(), 0x0b), BADARITH);
    assert_eq!(
        run_unary(
            |m, h| m.emit_i_unary_minus(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            tagged(7).unwrap()
        ),
        tagged(-7).unwrap()
    );
    assert_eq!(
        run_unary(
            |m, h| m.emit_i_bnot(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            tagged(7).unwrap()
        ),
        tagged(!7).unwrap()
    );
    assert_eq!(
        run_unary(
            |m, h| m
                .emit_i_increment(ArgVal::X(0), 1, ArgVal::X(1), h)
                .unwrap(),
            tagged(7).unwrap()
        ),
        tagged(8).unwrap()
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn immediate_add_sub_cover_small_boundary_overflow_and_non_integer_fallbacks() {
    let add = |lhs, immediate| {
        run_binary(
            |m, h| {
                m.emit_i_plus(ArgVal::X(0), ArgVal::Immediate(immediate), ArgVal::X(1), h)
                    .unwrap()
            },
            lhs,
            0,
        )
    };
    let sub = |lhs, immediate| {
        run_binary(
            |m, h| {
                m.emit_i_minus(ArgVal::X(0), ArgVal::Immediate(immediate), ArgVal::X(1), h)
                    .unwrap()
            },
            lhs,
            0,
        )
    };
    let one = tagged(1).unwrap();
    assert_eq!(add(tagged(40).unwrap(), one), tagged(41).unwrap());
    assert_eq!(sub(tagged(40).unwrap(), one), tagged(39).unwrap());
    assert_eq!(add(tagged((1 << 59) - 1).unwrap(), one), OVERFLOW);
    assert_eq!(sub(tagged(-(1 << 59)).unwrap(), one), OVERFLOW);
    assert_eq!(add(0x0b, one), BADARITH);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn float_ops_preserve_ieee_results_and_reject_non_finite_values() {
    for (op, expected) in [(19, 3.5), (20, 0.5), (21, 3.0), (22, 4.0 / 3.0)] {
        let result = run_binary(
            |m, h| match op {
                19 => m
                    .emit_fadd(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap(),
                20 => m
                    .emit_fsub(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap(),
                21 => m
                    .emit_fmul(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap(),
                _ => m
                    .emit_fdiv(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                    .unwrap(),
            },
            2.0f64.to_bits(),
            1.5f64.to_bits(),
        );
        assert_eq!(f64::from_bits(result), expected);
    }
    assert_eq!(
        run_binary(
            |m, h| m
                .emit_fdiv(ArgVal::X(0), ArgVal::X(1), ArgVal::X(1), h)
                .unwrap(),
            1f64.to_bits(),
            0f64.to_bits()
        ),
        BADARITH
    );
    assert_eq!(
        run_unary(
            |m, h| m.emit_fnegate(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            2.5f64.to_bits()
        ),
        (-2.5f64).to_bits()
    );
    assert_eq!(
        run_unary(
            |m, h| m.emit_fload(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            2.5f64.to_bits()
        ),
        2.5f64.to_bits()
    );
    assert_eq!(
        run_unary(
            |m, h| m.emit_fstore(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            2.5f64.to_bits()
        ),
        2.5f64.to_bits()
    );
    assert_eq!(
        run_unary(
            |m, h| m.emit_fconv(ArgVal::X(0), ArgVal::X(1), h).unwrap(),
            tagged(12).unwrap()
        ),
        12.0f64.to_bits()
    );
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn arithmetic_execution_requires_aarch64() {
    assert_eq!(std::mem::size_of::<usize>(), 8);
}

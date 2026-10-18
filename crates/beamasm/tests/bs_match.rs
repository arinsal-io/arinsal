use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bs_segments::BsmCommand,
    enter_native,
    module::{ArgVal, BeamModuleAssembler},
    rt,
};
use arinsal_term::{ProcessHeap, Term, TermBuilder};
use std::{cell::RefCell, collections::VecDeque};

thread_local! {
    static BYTE_VALUES: RefCell<VecDeque<u8>> = const { RefCell::new(VecDeque::new()) };
    static RETURN_VALUES: RefCell<VecDeque<u64>> = const { RefCell::new(VecDeque::new()) };
}

extern "C" fn match_helper(
    _process: *mut ProcessHeader,
    _op: u32,
    _ctx: u64,
    _size: u64,
    _unit: u64,
) -> u64 {
    RETURN_VALUES
        .with(|values| values.borrow_mut().pop_front())
        .unwrap_or_else(|| {
            BYTE_VALUES.with(|values| {
                values
                    .borrow_mut()
                    .pop_front()
                    .and_then(|byte| Term::small(i64::from(byte)))
                    .map_or(1, rt::term_bits)
            })
        })
}

extern "C" fn gc_helper(
    _header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _need_words: usize,
    _live: usize,
    _fcalls: i32,
) -> i32 {
    0
}

#[cfg(target_arch = "aarch64")]
fn run_native(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
) {
    let _ = run_native_configured(emit);
}

#[cfg(target_arch = "aarch64")]
fn run_native_configured(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
) -> u64 {
    run_native_offset(emit, 0, &[0x5a; 1000]).0
}

#[cfg(target_arch = "aarch64")]
fn run_native_offset(
    emit: impl FnOnce(&mut BeamModuleAssembler) -> Result<(), arinsal_beamasm::module::ModuleError>,
    bit_offset: usize,
    bytes: &[u8],
) -> (u64, u64) {
    let mut heap = ProcessHeap::with_words(4096);
    let mut builder = TermBuilder::new(&mut heap);
    let binary = builder.binary(bytes).unwrap();
    let sliced = builder
        .sub_binary(binary, bit_offset, bytes.len() * 8 - bit_offset)
        .unwrap();
    let context = builder.match_context(sliced).unwrap();

    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_enter_frame().unwrap();
    emit(&mut asm).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    asm.emit_i_func_label(99).unwrap();
    asm.emit_leave_frame().unwrap();
    asm.emit_raw(|e| {
        e.mov_const(Gpr::x(26), 77)?;
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = context;
    registers.x_reg_array[1] = Term::small(1).unwrap();
    let mut stack = [0_u64; 128];
    let (htop, hend) = heap.heap_cursor();
    let (heap_start, _) = heap.heap_bounds();
    let mut header = ProcessHeader {
        htop,
        heap: heap_start,
        hend,
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let result = enter_native(&mut header, &mut registers, &module.entry(1).unwrap());
    assert_eq!(result, ExitReason::Returned);
    (
        registers.x_reg_array[1].tagged_word(),
        registers.x_reg_array[2].tagged_word(),
    )
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_start_match3() {
    run_native(|a| {
        a.emit_i_bs_start_match3(ArgVal::X(0), 1, 99, ArgVal::X(1), match_helper, gc_helper)
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_match_test_heap() {
    run_native(|a| {
        a.emit_i_bs_match_segments(
            ArgVal::X(0),
            99,
            0,
            1,
            &[BsmCommand::EnsureAtLeast { size: 8, unit: 1 }],
            match_helper,
            match_command,
            gc_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_position() {
    run_native(|a| a.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_set_position() {
    run_native(|a| a.emit_i_bs_set_position(ArgVal::X(0), ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_bs_test_unit() {
    run_native(|a| a.emit_bs_test_unit(ArgVal::X(0), 8, 99));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_bs_test_tail2() {
    run_native(|a| {
        a.emit_bs_test_tail2(
            ArgVal::X(0),
            ArgVal::Immediate(rt::term_bits(Term::small(8000).unwrap())),
            99,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_skip_bits2() {
    run_native(|a| {
        a.emit_i_bs_skip_bits2(
            ArgVal::X(0),
            ArgVal::Immediate(rt::term_bits(Term::small(1).unwrap())),
            1,
            99,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_integer_8() {
    run_native(|a| a.emit_i_bs_get_integer_8(ArgVal::X(0), 99, ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_integer_16() {
    run_native(|a| a.emit_i_bs_get_integer_16(ArgVal::X(0), 99, ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_integer_32() {
    run_native(|a| a.emit_i_bs_get_integer_32(ArgVal::X(0), 99, ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_integer() {
    run_native(|a| {
        a.emit_i_bs_get_integer(
            ArgVal::X(0),
            99,
            ArgVal::Immediate(rt::term_bits(Term::small(12).unwrap())),
            1,
            ArgVal::X(1),
            match_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_binary2() {
    run_native(|a| {
        a.emit_i_bs_get_binary2(
            ArgVal::X(0),
            99,
            1,
            ArgVal::Immediate(rt::term_bits(Term::small(8).unwrap())),
            1,
            ArgVal::X(1),
            match_helper,
            gc_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_binary_all2() {
    run_native(|a| a.emit_i_bs_get_binary_all2(ArgVal::X(0), 99, 8, ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_match_string() {
    run_native(|a| {
        a.emit_i_bs_match_string(
            ArgVal::X(0),
            99,
            ArgVal::Immediate((8 << 4) | 0xf),
            ArgVal::Literal(0),
            match_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_bs_get_tail() {
    run_native(|a| a.emit_bs_get_tail(ArgVal::X(0), ArgVal::X(1), 1, match_helper, gc_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_utf8() {
    run_native(|a| a.emit_i_bs_get_utf8(ArgVal::X(0), 99, ArgVal::X(1), match_helper));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_utf16() {
    run_native(|a| {
        a.emit_i_bs_get_utf16(
            ArgVal::X(0),
            99,
            ArgVal::Immediate(0),
            ArgVal::X(1),
            match_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_get_float2() {
    run_native(|a| {
        a.emit_i_bs_get_float2(
            ArgVal::X(0),
            99,
            1,
            ArgVal::Immediate(rt::term_bits(Term::small(32).unwrap())),
            1,
            ArgVal::X(1),
            match_helper,
            gc_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_i_bs_match() {
    run_native(|a| {
        a.emit_i_bs_match_segments(
            ArgVal::X(0),
            99,
            0,
            0,
            &[BsmCommand::EnsureExactly { size: 8000 }],
            match_helper,
            match_command,
            gc_helper,
        )
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_unaligned_match_context_and_fail_branch() {
    let result = run_native_offset(
        |asm| {
            asm.emit_bs_test_tail2(
                ArgVal::X(0),
                ArgVal::Immediate(rt::term_bits(Term::small(8000).unwrap())),
                99,
            )
        },
        1,
        &[0x5a; 1000],
    );
    assert_eq!(result.0, 77);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_byte_loop_over_thousand_byte_binary() {
    BYTE_VALUES.with(|values| *values.borrow_mut() = VecDeque::from(vec![0x5a; 1000]));
    let sum =
        run_native_configured(|asm| asm.emit_i_bs_sum_bytes_loop(ArgVal::X(0), 1000, match_helper));
    assert_eq!(sum, 90_000);
    BYTE_VALUES.with(|values| assert!(values.borrow().is_empty()));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_sub_binary_extraction() {
    // 16 bits of the 0x5a fixture are copied on-heap; the context then sits at bit 16.
    let actual = run_native_configured(|asm| {
        asm.emit_i_bs_get_binary2(
            ArgVal::X(0),
            99,
            1,
            ArgVal::Immediate(rt::term_bits(Term::small(16).unwrap())),
            1,
            ArgVal::X(2),
            match_helper,
            gc_helper,
        )?;
        asm.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(1), match_helper)
    });
    assert_eq!(actual, rt::term_bits(Term::small(16).unwrap()));
    // 80 bytes is past the 64-byte on-heap limit, so the slice is a shared sub-bits.
    let wide = run_native_configured(|asm| {
        asm.emit_i_bs_get_binary2(
            ArgVal::X(0),
            99,
            1,
            ArgVal::Immediate(rt::term_bits(Term::small(80).unwrap())),
            8,
            ArgVal::X(2),
            match_helper,
            gc_helper,
        )?;
        asm.emit_i_bs_get_position(ArgVal::X(0), ArgVal::X(1), match_helper)
    });
    assert_eq!(wide, rt::term_bits(Term::small(640).unwrap()));
    // The extracted sub-bits is not a match context; start_match must build one.
    let byte = run_native_configured(|asm| {
        asm.emit_i_bs_get_binary2(
            ArgVal::X(0),
            99,
            1,
            ArgVal::Immediate(rt::term_bits(Term::small(80).unwrap())),
            8,
            ArgVal::X(1),
            match_helper,
            gc_helper,
        )?;
        asm.emit_i_bs_start_match3(ArgVal::X(1), 1, 99, ArgVal::X(0), match_helper, gc_helper)?;
        int_segments(asm, &[(8, ArgVal::X(1))])
    });
    assert_eq!(byte, rt::term_bits(Term::small(0x5a).unwrap()));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_inline_fixed_integers() {
    let byte = run_native_configured(|asm| int_segments(asm, &[(8, ArgVal::X(1))]));
    assert_eq!(byte, rt::term_bits(Term::small(0x5a).unwrap()));
    let word = run_native_configured(|asm| int_segments(asm, &[(32, ArgVal::X(1))]));
    assert_eq!(word, rt::term_bits(Term::small(0x5a5a_5a5a).unwrap()));
}

#[cfg(target_arch = "aarch64")]
fn int_segments(
    asm: &mut BeamModuleAssembler,
    fields: &[(u64, ArgVal)],
) -> Result<(), arinsal_beamasm::module::ModuleError> {
    let commands: Vec<_> = fields
        .iter()
        .map(|&(size, dst)| BsmCommand::Integer {
            live: None,
            flags: 0,
            size,
            unit: 1,
            dst,
        })
        .collect();
    asm.emit_i_bs_match_segments(
        ArgVal::X(0),
        99,
        0,
        1,
        &commands,
        match_helper,
        match_command,
        gc_helper,
    )
}

extern "C" fn match_command(_process: *mut ProcessHeader, _kind: u64, _live: u64) -> u64 {
    0
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_utf8_multibyte() {
    // U+20AC EURO SIGN is the three-byte sequence E2 82 AC.
    let expected = rt::term_bits(Term::small(0x20ac).unwrap());
    let actual = run_native_offset(
        |asm| asm.emit_i_bs_get_utf8(ArgVal::X(0), 99, ArgVal::X(1), match_helper),
        0,
        &[0xe2, 0x82, 0xac, 0x41],
    );
    assert_eq!(actual.0, expected);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fused_header_integers() {
    let (len, tag) = run_native_offset(
        |asm| int_segments(asm, &[(8, ArgVal::X(2)), (16, ArgVal::X(1))]),
        0,
        &[0x01, 0x00, 0x0d, 0x07],
    );
    assert_eq!(tag, rt::term_bits(Term::small(1).unwrap()));
    assert_eq!(len, rt::term_bits(Term::small(13).unwrap()));
}

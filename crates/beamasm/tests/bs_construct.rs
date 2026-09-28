use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bs_construct::{BsConstructErrorHelper, BsConstructHelper, BsSegment, BsSegmentKind},
    enter_native,
    module::{ArgVal, BeamModuleAssembler},
    rt,
};
use std::{cell::RefCell, process::Command};

#[derive(Default)]
struct HookState {
    bytes: Vec<u8>,
    bit_len: usize,
    error_called: bool,
}

thread_local! {
    static STATE: RefCell<HookState> = RefCell::new(HookState::default());
}

extern "C" fn segment_hook(
    _process: *mut ProcessHeader,
    operation: u64,
    value: u64,
    size: u64,
    unit: u64,
) -> u64 {
    let kind = (operation & 0xff) as u32;
    let flags = operation >> 32;
    let bit_count = size.saturating_mul(unit);
    if (kind == BsSegmentKind::Integer as u32 && size == 0)
        || (kind > BsSegmentKind::String as u32 && kind != BsSegmentKind::PrivateAppend as u32)
    {
        return 0;
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match kind {
            0 | 5 => append_packed(&mut state, value, bit_count as usize, flags & 1 != 0),
            1 => append_packed(&mut state, value, bit_count as usize, flags & 1 != 0),
            2 => {
                state
                    .bytes
                    .extend_from_slice(&(f64::from_bits(value)).to_be_bytes());
                state.bit_len += 64;
            }
            3 => {
                let mut encoded = [0; 4];
                let text = char::from_u32(value as u32)
                    .unwrap()
                    .encode_utf8(&mut encoded);
                state.bytes.extend_from_slice(text.as_bytes());
                state.bit_len += text.len() * 8;
            }
            4 | 6 => append_packed(&mut state, value, bit_count as usize, false),
            _ => unreachable!(),
        }
    });
    1
}

extern "C" fn error_hook(_process: *mut ProcessHeader, _info: u32, _value: u64) -> u64 {
    STATE.with(|state| state.borrow_mut().error_called = true);
    1
}

extern "C" fn panic_segment_hook(
    _process: *mut ProcessHeader,
    _operation: u64,
    _value: u64,
    _size: u64,
    _unit: u64,
) -> u64 {
    panic!("fixed-size construction must use its inline emitter")
}

fn run_native_inline(segment: BsSegment) -> Vec<u8> {
    run_native_inline_segments(&[segment])
}

fn run_native_inline_segments(segments: &[BsSegment]) -> Vec<u8> {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_bs_create_bin(
        None,
        ArgVal::X(1),
        segments,
        panic_segment_hook as BsConstructHelper,
        error_hook as BsConstructErrorHelper,
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut output = [0_u64; 8];
    let base = output.as_mut_ptr();
    let mut header = ProcessHeader {
        htop: base,
        heap: base,
        hend: base.wrapping_add(output.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    let mut registers = SchedulerRegisters::default();
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    let written = header.htop as usize - base as usize;
    let bytes: Vec<_> = output.iter().flat_map(|word| word.to_ne_bytes()).collect();
    bytes[..written].to_vec()
}

fn append_packed(state: &mut HookState, value: u64, bits: usize, little: bool) {
    let value = if little && bits.is_multiple_of(8) {
        (0..bits / 8).fold(0_u64, |result, byte| {
            (result << 8) | ((value >> (byte * 8)) & 0xff)
        })
    } else {
        value
    };
    for index in 0..bits {
        let bit = (value >> (bits - index - 1)) & 1;
        let absolute_bit = state.bit_len;
        if absolute_bit.is_multiple_of(8) {
            state.bytes.push(0);
        }
        let offset = absolute_bit % 8;
        state.bytes[absolute_bit / 8] |= (bit as u8) << (7 - offset);
        state.bit_len += 1;
    }
}

fn erl_bytes(expr: &str) -> Vec<u8> {
    let eval = format!("io:format(\"~p\", [binary_to_list({expr})]), halt().");
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .expect("OTP 29 erl must be available");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let text = text.trim().trim_start_matches('[').trim_end_matches(']');
    if text.is_empty() {
        return Vec::new();
    }
    text.split(',').map(|byte| byte.parse().unwrap()).collect()
}

fn run_native(segments: &[BsSegment], badarg: bool) -> (u64, HookState) {
    STATE.with(|state| *state.borrow_mut() = HookState::default());
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_bs_create_bin(
        None,
        ArgVal::X(1),
        segments,
        segment_hook as BsConstructHelper,
        error_hook as BsConstructErrorHelper,
    )
    .unwrap();
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
    let module = asm.finalize().unwrap();
    let mut registers = SchedulerRegisters::default();
    let mut stack = [0_u64; 64];
    let mut header = ProcessHeader {
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    let value = registers.x_reg_array[1];
    let state = STATE.with(|state| std::mem::take(&mut *state.borrow_mut()));
    assert_eq!(state.error_called, badarg);
    (value, state)
}

fn segment(kind: BsSegmentKind, src: u64, size: u64, unit: u32, flags: u32) -> BsSegment {
    BsSegment {
        kind,
        src: ArgVal::Immediate(src),
        size: ArgVal::Immediate(size),
        unit,
        flags,
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_literal_bytes() {
    let bytes = run_native_inline(segment(BsSegmentKind::String, 0x010203, 24, 1, 0));
    assert_eq!(bytes, erl_bytes("<<1,2,3>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_int_endian() {
    let bytes = run_native_inline_segments(&[
        segment(BsSegmentKind::Integer, 0x1234, 16, 1, 0),
        segment(BsSegmentKind::Integer, 0x01020304, 32, 1, 1),
    ]);
    assert_eq!(bytes, erl_bytes("<<16#1234:16/big,16#01020304:32/little>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_append() {
    let (_, state) = run_native(
        &[
            segment(BsSegmentKind::Append, 0x010203, 24, 1, 0),
            segment(BsSegmentKind::Integer, 0, 8, 1, 0),
        ],
        false,
    );
    assert_eq!(state.bytes, erl_bytes("<<(<<1,2,3>>)/binary,0>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_unaligned() {
    let bytes = run_native_inline_segments(&[
        segment(BsSegmentKind::Integer, 1, 7, 1, 0),
        segment(BsSegmentKind::Integer, 0x101, 9, 1, 0),
    ]);
    assert_eq!(bytes, erl_bytes("<<1:7,16#101:9>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_float() {
    let (_, state) = run_native(
        &[segment(BsSegmentKind::Float, 1.5_f64.to_bits(), 64, 1, 0)],
        false,
    );
    assert_eq!(state.bytes, erl_bytes("<<1.5/float>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_utf8() {
    let bytes = run_native_inline(segment(BsSegmentKind::Utf8, 0x20ac, 0, 1, 0));
    assert_eq!(bytes, erl_bytes("<<16#20ac/utf8>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_bad_size_badarg() {
    let (_, state) = run_native(&[segment(BsSegmentKind::Integer, 3, 0, 1, 0)], true);
    assert!(state.bytes.is_empty());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_inline_int_no_segment_hook() {
    let bytes = run_native_inline(segment(BsSegmentKind::Integer, 0x1234, 16, 1, 0));
    assert_eq!(bytes, erl_bytes("<<16#1234:16>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_inline_binary_no_segment_hook() {
    let bytes = run_native_inline(segment(BsSegmentKind::Binary, 0x010203, 24, 1, 0));
    assert_eq!(bytes, erl_bytes("<<1,2,3>>"));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_inline_zero_no_segment_hook() {
    let bytes = run_native_inline(segment(BsSegmentKind::Integer, 0, 16, 1, 0));
    assert_eq!(bytes, erl_bytes("<<0:16>>"));
}

#[test]
fn native_code_path_is_available() {
    let _ = rt::term_bits(arinsal_term::Term::small(1).unwrap());
}

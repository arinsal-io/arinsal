use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters,
    bs_construct::{BsConstructErrorHelper, BsConstructHelper, BsSegment, BsSegmentKind},
    enter_native,
    module::{ArgVal, BeamModuleAssembler},
};
use arinsal_term::{ProcessHeap, Term, TermBuilder};
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

fn heap_word(tagged: u64, index: usize) -> u64 {
    arinsal_beamasm::rt::read_heap_word(tagged, index)
}

fn binary_bit(term: u64, index: usize) -> Option<u8> {
    let tag = heap_word(term, 0) & 63;
    let (data, start, length) = if tag == 0x20 {
        (term & !7, 0, heap_word(term, 1) as usize)
    } else if tag == 0x24 {
        let base = heap_word(term, 1) & !3;
        let start = heap_word(term, 2) as usize;
        let end = heap_word(term, 3) as usize;
        let original = heap_word(term, 4);
        let original_header = heap_word(original, 0) & 63;
        let adjust = if original_header == 0x28 {
            ((heap_word(original, 2) >> 1) & 3) as usize
        } else {
            0
        };
        (base + adjust as u64, start - adjust * 8, end - start)
    } else {
        return None;
    };
    if index >= length {
        return None;
    }
    let absolute = start + index;
    let address = if tag == 0x20 {
        data + 16 + (absolute / 8) as u64
    } else {
        data + (absolute / 8) as u64
    };
    let aligned = address & !7;
    let word = arinsal_beamasm::rt::read_heap_word(aligned | 2, 0);
    Some(((word.to_ne_bytes()[(address & 7) as usize] >> (7 - absolute % 8)) & 1) as u8)
}

fn source_bytes(term: u64, bits: usize) -> Option<Vec<u8>> {
    if bits > 8 * 1024 * 1024 {
        return None;
    }
    let mut result = vec![0; bits.div_ceil(8)];
    for index in 0..bits {
        let bit = binary_bit(term, index)?;
        result[index / 8] |= bit << (7 - index % 8);
    }
    Some(result)
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
    let bit_count = size.saturating_mul(unit) as usize;
    let source = if matches!(kind, 0 | 4 | 6) {
        match source_bytes(value, bit_count) {
            Some(bytes) => Some(bytes),
            None => {
                if kind == 0 {
                    return 0;
                }
                None
            }
        }
    } else {
        None
    };
    if kind == BsSegmentKind::Binary as u32 && source.is_none() {
        return 0;
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        match kind {
            0 | 4 | 6 => {
                let Some(source) = source else { return };
                for index in 0..bit_count {
                    let bit = (source[index / 8] >> (7 - index % 8)) & 1;
                    let destination = state.bit_len;
                    if destination.is_multiple_of(8) {
                        state.bytes.push(0);
                    }
                    state.bytes[destination / 8] |= bit << (7 - destination % 8);
                    state.bit_len += 1;
                }
            }
            1 | 5 => append_packed(&mut state, value, bit_count, flags & 1 != 0),
            _ => (),
        }
    });
    1
}

extern "C" fn error_hook(_process: *mut ProcessHeader, _info: u32, _value: u64) -> u64 {
    STATE.with(|state| state.borrow_mut().error_called = true);
    1
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
        let destination = state.bit_len;
        if destination.is_multiple_of(8) {
            state.bytes.push(0);
        }
        state.bytes[destination / 8] |= (bit as u8) << (7 - destination % 8);
        state.bit_len += 1;
    }
}

fn erl_bytes(expr: &str) -> Vec<u8> {
    let eval = format!(
        "F = fun Loop(<<>>) -> []; Loop(<<B:8, R/bitstring>>) -> [B|Loop(R)]; Loop(Tail) -> <<N:(bit_size(Tail))>> = Tail, [N bsl (8-bit_size(Tail))] end, io:format(\"~p\", [F(begin {expr} end)]), halt()."
    );
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .expect("OTP 29 erl must be available");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let text = text.trim().trim_start_matches('[').trim_end_matches(']');
    if text.is_empty() {
        return Vec::new();
    }
    text.split(',')
        .map(|byte| byte.trim().parse().unwrap())
        .collect()
}

fn run_native(segments: &[BsSegment], source: Term, badarg: bool) -> HookState {
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
    registers.x_reg_array[0] = arinsal_beamasm::rt::term_bits(source);
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
    let state = STATE.with(|state| std::mem::take(&mut *state.borrow_mut()));
    assert_eq!(state.error_called, badarg);
    state
}

fn binary_segment(size: u64, unit: u32) -> BsSegment {
    BsSegment {
        kind: BsSegmentKind::Binary,
        src: ArgVal::X(0),
        size: ArgVal::Immediate(size),
        unit,
        flags: 0,
    }
}

fn source(bytes: &[u8]) -> (ProcessHeap, Term) {
    let mut heap = ProcessHeap::new();
    let term = TermBuilder::new(&mut heap).binary(bytes).unwrap();
    (heap, term)
}

fn erl_binary_expr(bytes: &[u8]) -> String {
    format!(
        "<<{}>>",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_heap_binary() {
    let (heap, term) = source(&[1, 2, 3, 4]);
    let state = run_native(&[binary_segment(32, 1)], term, false);
    assert_eq!(state.bytes, erl_bytes("<<1,2,3,4>>"));
    drop(heap);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_offheap_binary() {
    let bytes: Vec<u8> = (0..100).collect();
    let (heap, term) = source(&bytes);
    let state = run_native(&[binary_segment(800, 1)], term, false);
    let expr = erl_binary_expr(&bytes);
    assert_eq!(state.bytes, erl_bytes(&expr));
    drop(heap);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_unaligned_subbinary() {
    let mut heap = ProcessHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let mut original_bytes = vec![0; 100];
    original_bytes[..3].copy_from_slice(&[0b1011_0010, 0b1101_0110, 0b1000_0000]);
    let original = builder.binary(&original_bytes).unwrap();
    let term = builder.sub_binary(original, 3, 13).unwrap();
    assert_eq!(
        arinsal_beamasm::rt::read_heap_word(arinsal_beamasm::rt::term_bits(term), 0) & 63,
        0x24
    );
    let state = run_native(&[binary_segment(13, 1)], term, false);
    let source_expr = erl_binary_expr(&original_bytes);
    assert_eq!(
        state.bytes,
        erl_bytes(&format!(
            "<<_:3, B:13/bitstring, _/bitstring>> = {source_expr}, <<B/bitstring>>"
        ))
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_append() {
    let (heap, term) = source(&[1, 2, 3]);
    let segments = [
        BsSegment {
            kind: BsSegmentKind::Append,
            src: ArgVal::X(0),
            size: ArgVal::Immediate(24),
            unit: 1,
            flags: 0,
        },
        BsSegment {
            kind: BsSegmentKind::Integer,
            src: ArgVal::Immediate(7),
            size: ArgVal::Immediate(8),
            unit: 1,
            flags: 0,
        },
    ];
    let state = run_native(&segments, term, false);
    assert_eq!(state.bytes, erl_bytes("<<(<<1,2,3>>)/binary,7>>"));
    drop(heap);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_private_append_loop() {
    let mut bytes = vec![0_u8; 65];
    for value in 0..10 {
        let (heap, term) = source(&bytes);
        let segments = [
            BsSegment {
                kind: BsSegmentKind::PrivateAppend,
                src: ArgVal::X(0),
                size: ArgVal::Immediate((bytes.len() * 8) as u64),
                unit: 1,
                flags: 0,
            },
            BsSegment {
                kind: BsSegmentKind::Integer,
                src: ArgVal::Immediate(value),
                size: ArgVal::Immediate(8),
                unit: 1,
                flags: 0,
            },
        ];
        let state = run_native(&segments, term, false);
        bytes = state.bytes;
        drop(heap);
    }
    assert_eq!(
        bytes,
        erl_bytes("<<(<<0:520>>)/binary,0,1,2,3,4,5,6,7,8,9>>")
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_short_binary_badarg() {
    let (heap, term) = source(&[1]);
    let state = run_native(&[binary_segment(16, 1)], term, true);
    assert!(state.bytes.is_empty());
    drop(heap);
}

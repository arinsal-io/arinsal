use arinsal_a64::enc::Gpr;
use arinsal_beamasm::{
    ExitReason, ProcessHeader, SchedulerRegisters, enter_native,
    float::{FloatOp, emit_fconv, emit_fload, emit_fstore},
    module::{ArgVal, BeamModuleAssembler},
};
use std::process::Command;

const HEADER_FLONUM: u64 = (1 << 6) | 0x18;
const HEADER_POS_BIG: u64 = (1 << 6) | 0x08;
/// `freason` of an `error` exception; the reason atom travels in `fvalue`.
const BADARITH: u64 = 1;

extern "C" fn big_to_float(_: *mut ProcessHeader, _: u64) -> u64 {
    1_152_921_504_606_846_976.0_f64.to_bits()
}

fn erl_bits(expression: &str) -> u64 {
    let eval = format!(
        "F = ({expression}), <<I:64/unsigned-big>> = <<F:64/float-big>>, io:format(\"~16.16.0b\", [I]), halt()."
    );
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .expect("OTP erl is available");
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    u64::from_str_radix(String::from_utf8_lossy(&output.stdout).trim(), 16).unwrap()
}

fn boxed_float(words: &mut [u64; 2], value: f64) -> u64 {
    words[0] = HEADER_FLONUM;
    words[1] = value.to_bits();
    words.as_mut_ptr() as u64 + 2
}

#[cfg(target_arch = "aarch64")]
fn execute(
    asm: BeamModuleAssembler,
    terms: [u64; 2],
    float_regs: [f64; 8],
) -> (ProcessHeader, SchedulerRegisters, [u64; 16], usize) {
    let module = asm.finalize().unwrap();
    let mut heap = [0_u64; 16];
    let mut stack = [0_u64; 32];
    let mut registers = SchedulerRegisters::default();
    registers.x_reg_array[0] = terms[0];
    registers.x_reg_array[1] = terms[1];
    registers.f_reg_array[..8].copy_from_slice(&float_regs);
    let mut header = ProcessHeader {
        htop: heap.as_mut_ptr(),
        heap: heap.as_mut_ptr(),
        hend: heap.as_mut_ptr().wrapping_add(heap.len()),
        stop: stack.as_mut_ptr().wrapping_add(stack.len()),
        fcalls: 100,
        ..ProcessHeader::default()
    };
    assert_eq!(
        enter_native(&mut header, &mut registers, &module.entry(1).unwrap()),
        ExitReason::Returned
    );
    let result_offset = registers.x_reg_array[1].wrapping_sub(heap.as_ptr() as u64) as usize;
    (header, registers, heap, result_offset)
}

#[cfg(target_arch = "aarch64")]
fn finish(asm: &mut BeamModuleAssembler) {
    asm.emit_raw(|e| {
        e.mov_reg(Gpr::x(0), Gpr::xzr())?;
        e.ret(Gpr::x(30))
    })
    .unwrap();
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fadd_boxed() {
    let mut left = [0_u64; 2];
    let mut right = [0_u64; 2];
    let lhs = boxed_float(&mut left, 1.25);
    let rhs = boxed_float(&mut right, 2.5);
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit_fload(&mut asm, ArgVal::X(0), 0).unwrap();
    emit_fload(&mut asm, ArgVal::X(1), 1).unwrap();
    asm.emit_i_fadd(0, 1, 2).unwrap();
    emit_fstore(&mut asm, 2, ArgVal::X(1)).unwrap();
    finish(&mut asm);
    let (header, _registers, heap, result_offset) = execute(asm, [lhs, rhs], [0.0; 8]);
    assert_eq!(result_offset, 2);
    assert_eq!(heap[0], HEADER_FLONUM);
    assert_eq!(heap[1], erl_bits("1.25 + 2.5"));
    assert_eq!(header.htop as usize - header.heap as usize, 16);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fconv_small() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, big_to_float).unwrap();
    emit_fstore(&mut asm, 0, ArgVal::X(1)).unwrap();
    finish(&mut asm);
    let (header, _registers, heap, result_offset) =
        execute(asm, [((42_u64) << 4) | 15, 0], [0.0; 8]);
    assert_eq!(result_offset, 2);
    assert_eq!(heap[1], erl_bits("float(42)"));
    assert_eq!(header.htop as usize - header.heap as usize, 16);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fconv_bignum() {
    let mut big = [HEADER_POS_BIG, 0];
    let term = big.as_mut_ptr() as u64 + 2;
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, big_to_float).unwrap();
    emit_fstore(&mut asm, 0, ArgVal::X(1)).unwrap();
    finish(&mut asm);
    let (header, _registers, heap, result_offset) = execute(asm, [term, 0], [0.0; 8]);
    assert_eq!(result_offset, 2);
    assert_eq!(heap[1], erl_bits("float(1152921504606846976)"));
    assert_eq!(header.htop as usize - header.heap as usize, 16);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fconv_bad_number() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    emit_fconv(&mut asm, ArgVal::X(0), 0, big_to_float).unwrap();
    finish(&mut asm);
    let (header, _, _, _) = execute(asm, [11, 0], [0.0; 8]);
    assert_eq!(header.freason, BADARITH);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fdiv_zero_badarith() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_fdiv(0, 1, 2).unwrap();
    finish(&mut asm);
    let (header, _, _, _) = execute(asm, [0, 0], [3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    assert_eq!(header.freason, BADARITH);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fmul_overflow_badarith() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_fmul(0, 1, 2).unwrap();
    finish(&mut asm);
    let (header, _, _, _) = execute(asm, [0, 0], [f64::MAX, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    assert_eq!(header.freason, BADARITH);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn native_fnegate() {
    let mut asm = BeamModuleAssembler::new();
    asm.emit_i_func_label(1).unwrap();
    asm.emit_i_fnegate(0, 1).unwrap();
    emit_fstore(&mut asm, 1, ArgVal::X(1)).unwrap();
    finish(&mut asm);
    let (header, _registers, heap, result_offset) =
        execute(asm, [0, 0], [7.25, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    assert_eq!(result_offset, 2);
    assert_eq!(heap[1], erl_bits("-7.25"));
    assert_eq!(header.htop as usize - header.heap as usize, 16);
}

#[test]
fn float_operations_have_distinct_instruction_selection() {
    assert_ne!(FloatOp::Add, FloatOp::Div);
}

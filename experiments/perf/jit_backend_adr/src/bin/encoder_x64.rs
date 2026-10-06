//! Measure the public x64 instruction encoder shipped with Cranelift 0.136.1.

use cranelift_assembler_x64::{Fixed, Inst, Registers, Simm32, inst};
use std::hint::black_box;
use std::time::Instant;

struct Regs;

impl Registers for Regs {
    type ReadGpr = u8;
    type ReadWriteGpr = u8;
    type WriteGpr = u8;
    type ReadXmm = u8;
    type ReadWriteXmm = u8;
    type WriteXmm = u8;
}

fn emit(ops: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(ops * 6 + 1);
    for _ in 0..ops {
        let add: Inst<Regs> = inst::addq_i_sxl::new(Fixed(0), Simm32::new(1)).into();
        add.encode(&mut buffer);
    }
    let ret: Inst<Regs> = inst::retq_zo::new().into();
    ret.encode(&mut buffer);
    buffer
}

fn main() {
    let ops = 999;
    let mut samples = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        for _ in 0..1000 {
            black_box(emit(ops));
        }
        samples.push(start.elapsed().as_nanos() as f64 / 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "x64_encoder_1000_ops_median_us={:.1} code_bytes={} (encode only, host is AArch64)",
        samples[samples.len() / 2] / 1000.0,
        emit(ops).len()
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn add_and_return_have_expected_x64_encoding() {
        assert_eq!(super::emit(1), [0x48, 0x05, 1, 0, 0, 0, 0xc3]);
    }
}

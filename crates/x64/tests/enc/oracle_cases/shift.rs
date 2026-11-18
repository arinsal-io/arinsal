//! Immediate and CL-controlled shifts and rotates.

use super::*;

type ImmOp = fn(&mut Emitter, Gp, i64) -> Result<(), EncodeError>;
type RegOp = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    let operations: [(&str, ImmOp, RegOp); 5] = [
        ("shl", Emitter::shl_ri, Emitter::shl_rr),
        ("shr", Emitter::shr_ri, Emitter::shr_rr),
        ("sar", Emitter::sar_ri, Emitter::sar_rr),
        ("rol", Emitter::rol_ri, Emitter::rol_rr),
        ("ror", Emitter::ror_ri, Emitter::ror_rr),
    ];
    for (mnemonic, imm_emit, reg_emit) in operations {
        for size in [1, 2, 4, 8] {
            for (dst_name, dst) in gps_few(size) {
                for imm in IMMS {
                    out.push(case(format!("{mnemonic} {dst_name}, {imm}"), move |e| {
                        imm_emit(e, dst, imm)
                    }));
                }
                for count_size in [1, 2, 4, 8] {
                    for (count_name, count) in gps_few(count_size) {
                        out.push(case(
                            format!("{mnemonic} {dst_name}, {count_name}"),
                            move |e| reg_emit(e, dst, count),
                        ));
                    }
                }
            }
        }
    }
}

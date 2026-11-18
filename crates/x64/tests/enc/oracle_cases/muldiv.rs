//! One-, two-, and three-operand multiplication and division cases.

use super::*;

type GpOp = fn(&mut Emitter, Gp) -> Result<(), EncodeError>;
type MemOp = fn(&mut Emitter, Mem) -> Result<(), EncodeError>;
type GpGp = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;
type GpMem = fn(&mut Emitter, Gp, Mem) -> Result<(), EncodeError>;
type GpGpImm = fn(&mut Emitter, Gp, Gp, i64) -> Result<(), EncodeError>;
type GpMemImm = fn(&mut Emitter, Gp, Mem, i64) -> Result<(), EncodeError>;
type GpImm = fn(&mut Emitter, Gp, i64) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    for (mnemonic, reg_emit, mem_emit) in [
        ("mul", Emitter::mul_r as GpOp, Emitter::mul_m as MemOp),
        ("imul", Emitter::imul_r as GpOp, Emitter::imul_m as MemOp),
        ("div", Emitter::div_r as GpOp, Emitter::div_m as MemOp),
        ("idiv", Emitter::idiv_r as GpOp, Emitter::idiv_m as MemOp),
    ] {
        for size in [1, 2, 4, 8] {
            for (name, reg) in gps(size) {
                out.push(case(format!("{mnemonic} {name}"), move |e| {
                    reg_emit(e, reg)
                }));
            }
        }
        for size in [0, 1, 2, 4, 8, 16] {
            for (name, mem) in mems(size).into_iter().step_by(11) {
                out.push(case(format!("{mnemonic} {name}"), move |e| {
                    mem_emit(e, mem)
                }));
            }
        }
    }

    let imul_rr: GpGp = Emitter::imul_rr;
    let imul_rm: GpMem = Emitter::imul_rm;
    let imul_rri: GpGpImm = Emitter::imul_rri;
    let imul_rmi: GpMemImm = Emitter::imul_rmi;
    let imul_ri: GpImm = Emitter::imul_ri;
    for dst_size in [1, 2, 4, 8] {
        for (dst_name, dst) in gps_few(dst_size) {
            for src_size in [1, 2, 4, 8] {
                for (src_name, src) in gps_few(src_size) {
                    out.push(case(format!("imul {dst_name}, {src_name}"), move |e| {
                        imul_rr(e, dst, src)
                    }));
                }
            }
            for mem_size in [0, 1, 2, 4, 8, 16] {
                for (mem_name, mem) in mems(mem_size).into_iter().step_by(17) {
                    out.push(case(format!("imul {dst_name}, {mem_name}"), move |e| {
                        imul_rm(e, dst, mem)
                    }));
                }
            }
            for imm in IMMS {
                out.push(case(format!("imul {dst_name}, {imm}"), move |e| {
                    imul_ri(e, dst, imm)
                }));
            }
            if dst_size != 1 {
                for (src_name, src) in gps_few(dst_size) {
                    for imm in IMMS {
                        out.push(case(
                            format!("imul {dst_name}, {src_name}, {imm}"),
                            move |e| imul_rri(e, dst, src, imm),
                        ));
                    }
                }
                for mem_size in [0, 1, 2, 4, 8, 16] {
                    for (mem_name, mem) in mems(mem_size).into_iter().step_by(23) {
                        for imm in IMMS {
                            out.push(case(
                                format!("imul {dst_name}, {mem_name}, {imm}"),
                                move |e| imul_rmi(e, dst, mem, imm),
                            ));
                        }
                    }
                }
            }
        }
    }

    out.push(case("cqo", |e| e.cqo()));
    out.push(case("cdq", |e| e.cdq()));
}

//! Indirect control transfer and return cases.

use super::*;

type GpOp = fn(&mut Emitter, Gp) -> Result<(), EncodeError>;
type MemOp = fn(&mut Emitter, Mem) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    for (mnemonic, emit) in [
        ("call", Emitter::call_r as GpOp),
        ("jmp", Emitter::jmp_r as GpOp),
    ] {
        for size in [1, 2, 4, 8] {
            for (name, reg) in gps(size) {
                out.push(case(format!("{mnemonic} {name}"), move |e| emit(e, reg)));
            }
        }
    }
    for (mnemonic, emit) in [
        ("call", Emitter::call_m as MemOp),
        ("jmp", Emitter::jmp_m as MemOp),
    ] {
        for (name, mem) in mems(8) {
            out.push(case(format!("{mnemonic} {name}"), move |e| emit(e, mem)));
        }
    }
    out.push(case("ret", |e| e.ret()));
    for imm in IMMS {
        out.push(case(format!("ret {imm}"), move |e| e.ret_i(imm)));
    }
}

//! Push, pop, and frame teardown cases.

use super::*;

type GpOp = fn(&mut Emitter, Gp) -> Result<(), EncodeError>;
type MemOp = fn(&mut Emitter, Mem) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    for (mnemonic, emit) in [
        ("push", Emitter::push_r as GpOp),
        ("pop", Emitter::pop_r as GpOp),
    ] {
        for size in [1, 2, 4, 8] {
            for (name, reg) in gps(size) {
                out.push(case(format!("{mnemonic} {name}"), move |e| emit(e, reg)));
            }
        }
    }
    for (mnemonic, emit) in [
        ("push", Emitter::push_m as MemOp),
        ("pop", Emitter::pop_m as MemOp),
    ] {
        for size in [0, 1, 2, 4, 8, 16, 32] {
            for (name, mem) in mems(size).into_iter().step_by(7) {
                out.push(case(format!("{mnemonic} {name}"), move |e| emit(e, mem)));
            }
        }
    }
    out.push(case("leave", |e| e.leave()));
}

//! BMI1/BMI2, LZCNT, and POPCNT register forms.

use super::*;

type Three = fn(&mut Emitter, Gp, Gp, Gp) -> Result<(), EncodeError>;
type Two = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;

fn ids(size: u8) -> Vec<(String, Gp)> {
    [0, 1, 7, 8, 9, 15]
        .into_iter()
        .map(|id| {
            let (name, reg) = gps(size)
                .into_iter()
                .find(|(_, reg)| reg.id == id)
                .expect("register id exists");
            (name, reg)
        })
        .collect()
}

pub fn cases(out: &mut Vec<OCase>) {
    let three_ops: [(&str, Three); 5] = [
        ("andn", Emitter::andn_rrr),
        ("bzhi", Emitter::bzhi_rrr),
        ("mulx", Emitter::mulx_rrr),
        ("pext", Emitter::pext_rrr),
        ("sarx", Emitter::sarx_rrr),
    ];
    for (mnemonic, emit) in three_ops {
        for size in [1, 2, 4, 8] {
            let regs = ids(size);
            for (a_name, a) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                for (b_name, b) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                    for (c_name, c) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                        out.push(case(
                            format!("{mnemonic} {a_name}, {b_name}, {c_name}"),
                            move |e| emit(e, a, b, c),
                        ));
                    }
                }
            }
        }
        for &(a_size, b_size, c_size) in &[(4, 8, 4), (8, 4, 8), (1, 4, 8), (2, 8, 4)] {
            for (a_name, a) in ids(a_size).into_iter().take(3) {
                for (b_name, b) in ids(b_size).into_iter().take(3) {
                    for (c_name, c) in ids(c_size).into_iter().take(3) {
                        out.push(case(
                            format!("{mnemonic} {a_name}, {b_name}, {c_name}"),
                            move |e| emit(e, a, b, c),
                        ));
                    }
                }
            }
        }
    }

    let shift_ops: [(&str, Three); 2] = [("shlx", Emitter::shlx_rrr), ("shrx", Emitter::shrx_rrr)];
    for (mnemonic, emit) in shift_ops {
        for size in [1, 2, 4, 8] {
            let regs = ids(size);
            for (a_name, a) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                for (b_name, b) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                    for (c_name, c) in regs.iter().map(|(name, reg)| (name.clone(), *reg)) {
                        out.push(case(
                            format!("{mnemonic} {a_name}, {b_name}, {c_name}"),
                            move |e| emit(e, a, b, c),
                        ));
                    }
                }
            }
        }
    }

    let two_ops: [(&str, Two); 3] = [
        ("lzcnt", Emitter::lzcnt_rr),
        ("tzcnt", Emitter::tzcnt_rr),
        ("popcnt", Emitter::popcnt_rr),
    ];
    for (mnemonic, emit) in two_ops {
        for dst_size in [1, 2, 4, 8] {
            for (dst_name, dst) in ids(dst_size) {
                for src_size in [1, 2, 4, 8] {
                    for (src_name, src) in ids(src_size) {
                        out.push(case(
                            format!("{mnemonic} {dst_name}, {src_name}"),
                            move |e| emit(e, dst, src),
                        ));
                    }
                }
            }
        }
    }
}

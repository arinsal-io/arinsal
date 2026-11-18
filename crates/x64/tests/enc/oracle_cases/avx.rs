//! `vpxor` (VEX reference family).

use super::*;

pub fn cases(out: &mut Vec<OCase>) {
    let ids = [0u8, 1, 7, 8, 9, 15];
    for &d in &ids {
        for &a in &ids {
            for &b in &ids {
                out.push(case(format!("vpxor xmm{d}, xmm{a}, xmm{b}"), move |e| {
                    e.vpxor_xxx(Xmm(d), Xmm(a), Xmm(b))
                }));
                out.push(case(format!("vpxor ymm{d}, ymm{a}, ymm{b}"), move |e| {
                    e.vpxor_yyy(Ymm(d), Ymm(a), Ymm(b))
                }));
            }
            for (mn, mem) in mems(16).into_iter().step_by(3) {
                out.push(case(format!("vpxor xmm{d}, xmm{a}, {mn}"), move |e| {
                    e.vpxor_xxm(Xmm(d), Xmm(a), mem)
                }));
            }
        }
    }
}

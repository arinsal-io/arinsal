//! Conditional moves and byte stores across the condition-code table.

use super::*;

type CmovR = fn(&mut Emitter, CondCode, Gp, Gp) -> Result<(), EncodeError>;
type CmovM = fn(&mut Emitter, CondCode, Gp, Mem) -> Result<(), EncodeError>;
type SetR = fn(&mut Emitter, CondCode, Gp) -> Result<(), EncodeError>;
type SetM = fn(&mut Emitter, CondCode, Mem) -> Result<(), EncodeError>;

const CONDITIONS: [(&str, CondCode); 16] = [
    ("o", CondCode::O),
    ("no", CondCode::NO),
    ("b", CondCode::B),
    ("ae", CondCode::AE),
    ("e", CondCode::E),
    ("ne", CondCode::NE),
    ("be", CondCode::BE),
    ("a", CondCode::A),
    ("s", CondCode::S),
    ("ns", CondCode::NS),
    ("p", CondCode::P),
    ("np", CondCode::NP),
    ("l", CondCode::L),
    ("ge", CondCode::GE),
    ("le", CondCode::LE),
    ("g", CondCode::G),
];

pub fn cases(out: &mut Vec<OCase>) {
    let cmov_r: CmovR = Emitter::cmovcc_rr;
    let cmov_m: CmovM = Emitter::cmovcc_rm;
    let set_r: SetR = Emitter::setcc_r;
    let set_m: SetM = Emitter::setcc_m;

    for &(cc_name, cc) in &CONDITIONS {
        for dst_size in [1, 2, 4, 8] {
            for (dst_name, dst) in gps_few(dst_size) {
                for src_size in [1, 2, 4, 8] {
                    for (src_name, src) in gps_few(src_size) {
                        out.push(case(
                            format!("cmov{cc_name} {dst_name}, {src_name}"),
                            move |e| cmov_r(e, cc, dst, src),
                        ));
                    }
                }
                for (mem_name, mem) in mems(0).into_iter().step_by(13) {
                    out.push(case(
                        format!("cmov{cc_name} {dst_name}, {mem_name}"),
                        move |e| cmov_m(e, cc, dst, mem),
                    ));
                }
            }
        }
        for size in [1, 2, 4, 8] {
            for (dst_name, dst) in gps(size) {
                out.push(case(format!("set{cc_name} {dst_name}"), move |e| {
                    set_r(e, cc, dst)
                }));
            }
        }
        for (mem_name, mem) in mems(0).into_iter().step_by(13) {
            out.push(case(format!("set{cc_name} {mem_name}"), move |e| {
                set_m(e, cc, mem)
            }));
        }
    }
}

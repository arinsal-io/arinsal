//! SSE scalar, conversion, and packed register/memory forms.

use super::*;

type Xx = fn(&mut Emitter, Xmm, Xmm) -> Result<(), EncodeError>;
type Xm = fn(&mut Emitter, Xmm, Mem) -> Result<(), EncodeError>;
type Mx = fn(&mut Emitter, Mem, Xmm) -> Result<(), EncodeError>;
type Xr = fn(&mut Emitter, Xmm, Gp) -> Result<(), EncodeError>;
type Rx = fn(&mut Emitter, Gp, Xmm) -> Result<(), EncodeError>;
type XrDest = fn(&mut Emitter, Gp, Xmm) -> Result<(), EncodeError>;
type RmDest = fn(&mut Emitter, Gp, Mem) -> Result<(), EncodeError>;

pub fn cases(out: &mut Vec<OCase>) {
    let reg_mem: [(&str, Xx, Xm); 15] = [
        ("movsd", Emitter::movsd_xx, Emitter::movsd_xm),
        ("movq", Emitter::movq_xx, Emitter::movq_xm),
        ("movdqa", Emitter::movdqa_xx, Emitter::movdqa_xm),
        ("movdqu", Emitter::movdqu_xx, Emitter::movdqu_xm),
        ("movups", Emitter::movups_xx, Emitter::movups_xm),
        ("pxor", Emitter::pxor_xx, Emitter::pxor_xm),
        ("punpcklqdq", Emitter::punpcklqdq_xx, Emitter::punpcklqdq_xm),
        ("andpd", Emitter::andpd_xx, Emitter::andpd_xm),
        ("ucomisd", Emitter::ucomisd_xx, Emitter::ucomisd_xm),
        ("comisd", Emitter::comisd_xx, Emitter::comisd_xm),
        ("addsd", Emitter::addsd_xx, Emitter::addsd_xm),
        ("subsd", Emitter::subsd_xx, Emitter::subsd_xm),
        ("mulsd", Emitter::mulsd_xx, Emitter::mulsd_xm),
        ("divsd", Emitter::divsd_xx, Emitter::divsd_xm),
        ("sqrtsd", Emitter::sqrtsd_xx, Emitter::sqrtsd_xm),
    ];
    for (mnemonic, rr, rm) in reg_mem {
        for dst in [0, 1, 7, 8, 9, 15] {
            for src in [0, 1, 7, 8, 9, 15] {
                out.push(case(format!("{mnemonic} xmm{dst}, xmm{src}"), move |e| {
                    rr(e, Xmm(dst), Xmm(src))
                }));
            }
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(19) {
                    out.push(case(format!("{mnemonic} xmm{dst}, {mem_name}"), move |e| {
                        rm(e, Xmm(dst), mem)
                    }));
                }
            }
        }
    }

    let stores: [(&str, Mx); 5] = [
        ("movsd", Emitter::movsd_mx),
        ("movq", Emitter::movq_mx),
        ("movdqa", Emitter::movdqa_mx),
        ("movdqu", Emitter::movdqu_mx),
        ("movups", Emitter::movups_mx),
    ];
    for (mnemonic, emit) in stores {
        for src in [0, 1, 7, 8, 9, 15] {
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(19) {
                    out.push(case(format!("{mnemonic} {mem_name}, xmm{src}"), move |e| {
                        emit(e, mem, Xmm(src))
                    }));
                }
            }
        }
    }

    let movq_xr: Xr = Emitter::movq_xr;
    let cvtsi2sd_xr: Xr = Emitter::cvtsi2sd_xr;
    let cvttsd2si_rx: XrDest = Emitter::cvttsd2si_rx;
    let cvtsi2sd_xm: Xm = Emitter::cvtsi2sd_xm;
    let cvttsd2si_rm: RmDest = Emitter::cvttsd2si_rm;
    let movq_rx: Rx = Emitter::movq_rx;
    for size in [1, 2, 4, 8] {
        for (name, reg) in gps(size) {
            for xmm in [0, 1, 8, 15] {
                out.push(case(format!("movq xmm{xmm}, {name}"), move |e| {
                    movq_xr(e, Xmm(xmm), reg)
                }));
                out.push(case(format!("movq {name}, xmm{xmm}"), move |e| {
                    movq_rx(e, reg, Xmm(xmm))
                }));
                out.push(case(format!("cvtsi2sd xmm{xmm}, {name}"), move |e| {
                    cvtsi2sd_xr(e, Xmm(xmm), reg)
                }));
                out.push(case(format!("cvttsd2si {name}, xmm{xmm}"), move |e| {
                    cvttsd2si_rx(e, reg, Xmm(xmm))
                }));
            }
        }
    }
    for xmm in [0, 1, 8, 15] {
        for size in [0, 1, 2, 4, 8, 16, 32] {
            for (mem_name, mem) in mems(size).into_iter().step_by(17) {
                out.push(case(format!("cvtsi2sd xmm{xmm}, {mem_name}"), move |e| {
                    cvtsi2sd_xm(e, Xmm(xmm), mem)
                }));
                out.push(case(format!("cvttsd2si r9, {mem_name}"), move |e| {
                    cvttsd2si_rm(e, R9, mem)
                }));
            }
        }
    }

    out.push(case("movdqu xmm16, xmm0", |e| e.movdqu_xx(Xmm(16), Xmm(0))));
    out.push(case("movdqu xmm0, xmm16", |e| e.movdqu_xx(Xmm(0), Xmm(16))));
    out.push(case("movdqu xmm0, xmmword ptr [rax+rsp*2]", |e| {
        e.movdqu_xm(Xmm(0), Mem::base_index(RAX, RSP, 1, 0, 16))
    }));
    out.push(case("btc rax, 63", |e| e.btc_ri(RAX, 63)));
    out.push(case("btc qword ptr [r13-8], 63", |e| {
        e.btc_mi(qword_ptr(R13, -8), 63)
    }));
    out.push(case("addpd xmm9, xmm15", |e| e.addpd_xx(Xmm(9), Xmm(15))));
    out.push(case("subpd xmm10, xmm8", |e| e.subpd_xx(Xmm(10), Xmm(8))));
    out.push(case("mulpd xmm4, xmm0", |e| e.mulpd_xx(Xmm(4), Xmm(0))));
    out.push(case("divpd xmm2, xmm3", |e| e.divpd_xx(Xmm(2), Xmm(3))));
    out.push(case("vaddpd xmm9, xmm1, xmm15", |e| {
        e.vaddpd_xxx(Xmm(9), Xmm(1), Xmm(15))
    }));
    out.push(case("vsubpd xmm10, xmm8, xmm0", |e| {
        e.vsubpd_xxx(Xmm(10), Xmm(8), Xmm(0))
    }));
    out.push(case("vmulpd xmm4, xmm7, xmm0", |e| {
        e.vmulpd_xxx(Xmm(4), Xmm(7), Xmm(0))
    }));
    out.push(case("vdivpd xmm2, xmm3, xmm15", |e| {
        e.vdivpd_xxx(Xmm(2), Xmm(3), Xmm(15))
    }));
}

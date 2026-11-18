//! AVX/AVX2 VEX forms, including register, memory, and immediate shapes.

use super::*;

type Xxx = fn(&mut Emitter, Xmm, Xmm, Xmm) -> Result<(), EncodeError>;
type Xxm = fn(&mut Emitter, Xmm, Xmm, Mem) -> Result<(), EncodeError>;
type VmSd = fn(&mut Emitter, Xmm, Xmm, Xmm) -> Result<(), EncodeError>;
type Yyy = fn(&mut Emitter, Ymm, Ymm, Ymm) -> Result<(), EncodeError>;
type Xxi = fn(&mut Emitter, Xmm, Xmm, i64) -> Result<(), EncodeError>;
type Xmi = fn(&mut Emitter, Xmm, Mem, i64) -> Result<(), EncodeError>;
type Yyi = fn(&mut Emitter, Ymm, Ymm, i64) -> Result<(), EncodeError>;
type Ymi = fn(&mut Emitter, Ymm, Mem, i64) -> Result<(), EncodeError>;
type Xx = fn(&mut Emitter, Xmm, Xmm) -> Result<(), EncodeError>;
type Xm = fn(&mut Emitter, Xmm, Mem) -> Result<(), EncodeError>;
type Mx = fn(&mut Emitter, Mem, Xmm) -> Result<(), EncodeError>;
type Yy = fn(&mut Emitter, Ymm, Ymm) -> Result<(), EncodeError>;
type Ym = fn(&mut Emitter, Ymm, Mem) -> Result<(), EncodeError>;
type My = fn(&mut Emitter, Mem, Ymm) -> Result<(), EncodeError>;
type Xxr = fn(&mut Emitter, Xmm, Xmm, Gp) -> Result<(), EncodeError>;
type XxmImm = fn(&mut Emitter, Xmm, Xmm, Mem, i64) -> Result<(), EncodeError>;
type Yymi = fn(&mut Emitter, Ymm, Ymm, Mem, i64) -> Result<(), EncodeError>;
type Xxri = fn(&mut Emitter, Xmm, Xmm, Gp, i64) -> Result<(), EncodeError>;
type Yyxi = fn(&mut Emitter, Ymm, Ymm, Xmm, i64) -> Result<(), EncodeError>;
type XGp = fn(&mut Emitter, Xmm, Gp) -> Result<(), EncodeError>;
type GpX = fn(&mut Emitter, Gp, Xmm) -> Result<(), EncodeError>;

const VREGS: [u8; 6] = [0, 1, 7, 8, 9, 15];

pub fn cases(out: &mut Vec<OCase>) {
    for (mnemonic, emit) in [
        ("vpxor", Emitter::vpxor_xxx as Xxx),
        ("vandpd", Emitter::vandpd_xxx as Xxx),
    ] {
        for d in VREGS {
            for a in VREGS {
                for b in VREGS {
                    out.push(case(
                        format!("{mnemonic} xmm{d}, xmm{a}, xmm{b}"),
                        move |e| emit(e, Xmm(d), Xmm(a), Xmm(b)),
                    ));
                }
                for (mem_name, mem) in mems(16).into_iter().step_by(11) {
                    out.push(case(
                        format!("{mnemonic} xmm{d}, xmm{a}, {mem_name}"),
                        move |e| {
                            if mnemonic == "vpxor" {
                                Emitter::vpxor_xxm(e, Xmm(d), Xmm(a), mem)
                            } else {
                                Emitter::vandpd_xxm(e, Xmm(d), Xmm(a), mem)
                            }
                        },
                    ));
                }
            }
        }
    }
    for (mnemonic, emit) in [
        ("vpxor", Emitter::vpxor_yyy as Yyy),
        ("vandpd", Emitter::vandpd_yyy as Yyy),
    ] {
        for d in VREGS {
            for a in VREGS {
                for b in VREGS {
                    out.push(case(
                        format!("{mnemonic} ymm{d}, ymm{a}, ymm{b}"),
                        move |e| emit(e, Ymm(d), Ymm(a), Ymm(b)),
                    ));
                }
                for (mem_name, mem) in mems(32).into_iter().step_by(11) {
                    out.push(case(
                        format!("{mnemonic} ymm{d}, ymm{a}, {mem_name}"),
                        move |e| {
                            if mnemonic == "vpxor" {
                                Emitter::vpxor_yym(e, Ymm(d), Ymm(a), mem)
                            } else {
                                Emitter::vandpd_yym(e, Ymm(d), Ymm(a), mem)
                            }
                        },
                    ));
                }
            }
        }
    }

    let cvtsi2sd: Xxr = Emitter::vcvtsi2sd_xxr;
    let cvtsi2sd_mem: Xxm = Emitter::vcvtsi2sd_xxm;
    for d in VREGS {
        for a in VREGS {
            for size in [1, 2, 4, 8] {
                for (src_name, src) in ids_for_gp(size) {
                    out.push(case(
                        format!("vcvtsi2sd xmm{d}, xmm{a}, {src_name}"),
                        move |e| cvtsi2sd(e, Xmm(d), Xmm(a), src),
                    ));
                }
            }
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(17) {
                    out.push(case(
                        format!("vcvtsi2sd xmm{d}, xmm{a}, {mem_name}"),
                        move |e| cvtsi2sd_mem(e, Xmm(d), Xmm(a), mem),
                    ));
                }
            }
        }
    }

    let xmm_movs: [(&str, Xx, Xm, Mx); 2] = [
        (
            "vmovdqu",
            Emitter::vmovdqu_xx,
            Emitter::vmovdqu_xm,
            Emitter::vmovdqu_mx,
        ),
        (
            "vmovups",
            Emitter::vmovups_xx,
            Emitter::vmovups_xm,
            Emitter::vmovups_mx,
        ),
    ];
    for (mnemonic, rr, rm, mr) in xmm_movs {
        for d in VREGS {
            for s in VREGS {
                out.push(case(format!("{mnemonic} xmm{d}, xmm{s}"), move |e| {
                    rr(e, Xmm(d), Xmm(s))
                }));
            }
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(19) {
                    out.push(case(format!("{mnemonic} xmm{d}, {mem_name}"), move |e| {
                        rm(e, Xmm(d), mem)
                    }));
                    out.push(case(format!("{mnemonic} {mem_name}, xmm{d}"), move |e| {
                        mr(e, mem, Xmm(d))
                    }));
                }
            }
        }
    }

    let vmovsd: VmSd = Emitter::vmovsd_xxx;
    for d in VREGS {
        for a in VREGS {
            for b in VREGS {
                out.push(case(format!("vmovsd xmm{d}, xmm{a}, xmm{b}"), move |e| {
                    vmovsd(e, Xmm(d), Xmm(a), Xmm(b))
                }));
            }
        }
    }
    for d in VREGS {
        for size in [0, 1, 2, 4, 8, 16, 32] {
            for (mem_name, mem) in mems(size).into_iter().step_by(23) {
                out.push(case(format!("vmovsd xmm{d}, {mem_name}"), move |e| {
                    Emitter::vmovsd_xm(e, Xmm(d), mem)
                }));
                out.push(case(format!("vmovsd {mem_name}, xmm{d}"), move |e| {
                    Emitter::vmovsd_mx(e, mem, Xmm(d))
                }));
            }
        }
    }

    let ymm_movs: [(&str, Yy, Ym, My); 2] = [
        (
            "vmovdqu",
            Emitter::vmovdqu_yy,
            Emitter::vmovdqu_ym,
            Emitter::vmovdqu_my,
        ),
        (
            "vmovups",
            Emitter::vmovups_yy,
            Emitter::vmovups_ym,
            Emitter::vmovups_my,
        ),
    ];
    for (mnemonic, rr, rm, mr) in ymm_movs {
        for d in VREGS {
            for s in VREGS {
                out.push(case(format!("{mnemonic} ymm{d}, ymm{s}"), move |e| {
                    rr(e, Ymm(d), Ymm(s))
                }));
            }
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(19) {
                    out.push(case(format!("{mnemonic} ymm{d}, {mem_name}"), move |e| {
                        rm(e, Ymm(d), mem)
                    }));
                    out.push(case(format!("{mnemonic} {mem_name}, ymm{d}"), move |e| {
                        mr(e, mem, Ymm(d))
                    }));
                }
            }
        }
    }

    let vpermil_xx: Xxi = Emitter::vpermilpd_xxi;
    let vpermil_xm: Xmi = Emitter::vpermilpd_xmi;
    let vpermil_yy: Yyi = Emitter::vpermilpd_yyi;
    let vpermil_ym: Ymi = Emitter::vpermilpd_ymi;
    let vpermq_yy: Yyi = Emitter::vpermq_yyi;
    let vpermq_ym: Ymi = Emitter::vpermq_ymi;
    for d in VREGS {
        for s in VREGS {
            for imm in IMMS {
                out.push(case(format!("vpermilpd xmm{d}, xmm{s}, {imm}"), move |e| {
                    vpermil_xx(e, Xmm(d), Xmm(s), imm)
                }));
                out.push(case(format!("vpermilpd ymm{d}, ymm{s}, {imm}"), move |e| {
                    vpermil_yy(e, Ymm(d), Ymm(s), imm)
                }));
                out.push(case(format!("vpermq ymm{d}, ymm{s}, {imm}"), move |e| {
                    vpermq_yy(e, Ymm(d), Ymm(s), imm)
                }));
            }
        }
        for size in [0, 1, 2, 4, 8, 16, 32] {
            for (mem_name, mem) in mems(size).into_iter().step_by(23) {
                for imm in IMMS {
                    out.push(case(
                        format!("vpermilpd xmm{d}, {mem_name}, {imm}"),
                        move |e| vpermil_xm(e, Xmm(d), mem, imm),
                    ));
                    out.push(case(
                        format!("vpermilpd ymm{d}, {mem_name}, {imm}"),
                        move |e| vpermil_ym(e, Ymm(d), mem, imm),
                    ));
                    out.push(case(
                        format!("vpermq ymm{d}, {mem_name}, {imm}"),
                        move |e| vpermq_ym(e, Ymm(d), mem, imm),
                    ));
                }
            }
        }
    }

    let vpinsrq_reg: Xxri = Emitter::vpinsrq_xxri;
    let vpinsrq_mem: XxmImm = Emitter::vpinsrq_xxmi;
    let vinsert_reg: Yyxi = Emitter::vinserti128_yyxi;
    let vinsert_mem: Yymi = Emitter::vinserti128_yymi;
    for d in VREGS {
        for a in VREGS {
            for size in [1, 2, 4, 8] {
                for (src_name, src) in ids_for_gp(size) {
                    for imm in IMMS {
                        out.push(case(
                            format!("vpinsrq xmm{d}, xmm{a}, {src_name}, {imm}"),
                            move |e| vpinsrq_reg(e, Xmm(d), Xmm(a), src, imm),
                        ));
                    }
                }
            }
            for size in [0, 1, 2, 4, 8, 16, 32] {
                for (mem_name, mem) in mems(size).into_iter().step_by(31) {
                    for imm in IMMS {
                        out.push(case(
                            format!("vpinsrq xmm{d}, xmm{a}, {mem_name}, {imm}"),
                            move |e| vpinsrq_mem(e, Xmm(d), Xmm(a), mem, imm),
                        ));
                        out.push(case(
                            format!("vinserti128 ymm{d}, ymm{a}, {mem_name}, {imm}"),
                            move |e| vinsert_mem(e, Ymm(d), Ymm(a), mem, imm),
                        ));
                    }
                }
            }
            for s in VREGS {
                for imm in IMMS {
                    out.push(case(
                        format!("vinserti128 ymm{d}, ymm{a}, xmm{s}, {imm}"),
                        move |e| vinsert_reg(e, Ymm(d), Ymm(a), Xmm(s), imm),
                    ));
                }
            }
        }
    }

    let vptest_xx: Xx = Emitter::vptest_xx;
    let vptest_xm: Xm = Emitter::vptest_xm;
    let vptest_yy: Yy = Emitter::vptest_yy;
    let vptest_ym: Ym = Emitter::vptest_ym;
    for d in VREGS {
        for s in VREGS {
            out.push(case(format!("vptest xmm{d}, xmm{s}"), move |e| {
                vptest_xx(e, Xmm(d), Xmm(s))
            }));
            out.push(case(format!("vptest ymm{d}, ymm{s}"), move |e| {
                vptest_yy(e, Ymm(d), Ymm(s))
            }));
        }
        for (mem_name, mem) in mems(16).into_iter().step_by(17) {
            out.push(case(format!("vptest xmm{d}, {mem_name}"), move |e| {
                vptest_xm(e, Xmm(d), mem)
            }));
        }
        for (mem_name, mem) in mems(32).into_iter().step_by(17) {
            out.push(case(format!("vptest ymm{d}, {mem_name}"), move |e| {
                vptest_ym(e, Ymm(d), mem)
            }));
        }
    }

    for d in VREGS {
        for s in VREGS {
            out.push(case(format!("vucomisd xmm{d}, xmm{s}"), move |e| {
                e.vucomisd_xx(Xmm(d), Xmm(s))
            }));
        }
        for (mem_name, mem) in mems(8).into_iter().step_by(17) {
            out.push(case(format!("vucomisd xmm{d}, {mem_name}"), move |e| {
                e.vucomisd_xm(Xmm(d), mem)
            }));
        }
    }
    out.push(case("vzeroupper", |e| e.vzeroupper()));

    let vmovq_xr: XGp = Emitter::vmovq_xr;
    let vmovq_rx: GpX = Emitter::vmovq_rx;
    for size in [1, 2, 4, 8] {
        for (name, reg) in ids_for_gp(size) {
            for xmm in VREGS {
                out.push(case(format!("vmovq xmm{xmm}, {name}"), move |e| {
                    vmovq_xr(e, Xmm(xmm), reg)
                }));
                out.push(case(format!("vmovq {name}, xmm{xmm}"), move |e| {
                    vmovq_rx(e, reg, Xmm(xmm))
                }));
            }
        }
    }
    for (mem_name, mem) in mems(8).into_iter().step_by(17) {
        for xmm in VREGS {
            out.push(case(format!("vmovq xmm{xmm}, {mem_name}"), move |e| {
                e.vmovq_xm(Xmm(xmm), mem)
            }));
            out.push(case(format!("vmovq {mem_name}, xmm{xmm}"), move |e| {
                e.vmovq_mx(mem, Xmm(xmm))
            }));
        }
    }

    out.push(case("vpxor xmm16, xmm0, xmm1", |e| {
        e.vpxor_xxx(Xmm(16), Xmm(0), Xmm(1))
    }));
    out.push(case("vpxor ymm0, ymm16, ymm1", |e| {
        e.vpxor_yyy(Ymm(0), Ymm(16), Ymm(1))
    }));
}

fn ids_for_gp(size: u8) -> Vec<(String, Gp)> {
    [0, 1, 8, 15]
        .into_iter()
        .map(|id| {
            gps(size)
                .into_iter()
                .find(|(_, reg)| reg.id == id)
                .expect("register id exists")
        })
        .collect()
}

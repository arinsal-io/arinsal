//! `mov`, `lea`, `movzx/movsx/movsxd`, `bswap`, `movbe`.

use super::*;

pub fn cases(out: &mut Vec<OCase>) {
    for size in [1u8, 2, 4, 8] {
        for (dn, d) in gps(size) {
            for (sn, s) in gps_few(size) {
                out.push(case(format!("mov {dn}, {sn}"), move |e| e.mov_rr(d, s)));
            }
            for imm in IMMS {
                out.push(case(format!("mov {dn}, {imm}"), move |e| e.mov_ri(d, imm)));
            }
        }
        for (rn, r) in gps_few(size) {
            for (mn, mem) in mems(size) {
                out.push(case(format!("mov {rn}, {mn}"), move |e| e.mov_rm(r, mem)));
                out.push(case(format!("mov {mn}, {rn}"), move |e| e.mov_mr(mem, r)));
            }
        }
        for (mn, mem) in mems(size).into_iter().step_by(3) {
            for imm in IMMS {
                out.push(case(format!("mov {mn}, {imm}"), move |e| {
                    e.mov_mi(mem, imm)
                }));
            }
        }
        if size > 1 {
            for (dn, d) in gps(size) {
                for (mn, mem) in mems(0).into_iter().step_by(4) {
                    out.push(case(format!("lea {dn}, {mn}"), move |e| e.lea(d, mem)));
                }
            }
        }
    }
    out.push(case("mov rax, ecx", |e| e.mov_rr(RAX, ECX)));
    out.push(case("mov ah, r9b", |e| e.mov_rr(AH, R9B)));
    out.push(case("mov ah, byte ptr [r8]", |e| {
        e.mov_rm(AH, byte_ptr(R8, 0))
    }));
    out.push(case("mov [rax], 1", |e| e.mov_mi(ptr(RAX, 0), 1)));
    out.push(case("lea al, [rax]", |e| e.lea(AL, ptr(RAX, 0))));

    // movzx / movsx / movsxd.
    for (m, rr, rm) in [
        (
            "movzx",
            Emitter::movzx_rr as fn(&mut Emitter, Gp, Gp) -> _,
            Emitter::movzx_rm as fn(&mut Emitter, Gp, Mem) -> _,
        ),
        ("movsx", Emitter::movsx_rr, Emitter::movsx_rm),
    ] {
        for dsize in [1u8, 2, 4, 8] {
            for ssize in [1u8, 2, 4, 8] {
                for (dn, d) in gps_few(dsize) {
                    for (sn, s) in gps_few(ssize) {
                        out.push(case(format!("{m} {dn}, {sn}"), move |e| rr(e, d, s)));
                    }
                    for msize in [0u8, 1, 2, 4] {
                        if ssize == 1 {
                            for (mn, mem) in mems(msize).into_iter().step_by(5) {
                                out.push(case(format!("{m} {dn}, {mn}"), move |e| rm(e, d, mem)));
                            }
                        }
                    }
                }
            }
        }
        out.push(case(format!("{m} ah, bl"), move |e| rr(e, AH, BL)));
        out.push(case(format!("{m} r9, ah"), move |e| rr(e, R9, AH)));
        out.push(case(format!("{m} ecx, ah"), move |e| rr(e, ECX, AH)));
    }
    for (dn, d) in gps(8).into_iter().chain(gps(4)) {
        for (sn, s) in gps_few(4).into_iter().chain(gps_few(8)) {
            out.push(case(format!("movsxd {dn}, {sn}"), move |e| {
                e.movsxd_rr(d, s)
            }));
        }
        for msize in [0u8, 4, 8] {
            for (mn, mem) in mems(msize).into_iter().step_by(5) {
                out.push(case(format!("movsxd {dn}, {mn}"), move |e| {
                    e.movsxd_rm(d, mem)
                }));
            }
        }
    }

    for size in [1u8, 2, 4, 8] {
        for (rn, r) in gps(size) {
            out.push(case(format!("bswap {rn}"), move |e| e.bswap(r)));
        }
        for (rn, r) in gps_few(size) {
            for (mn, mem) in mems(size).into_iter().step_by(4) {
                out.push(case(format!("movbe {rn}, {mn}"), move |e| {
                    e.movbe_rm(r, mem)
                }));
                out.push(case(format!("movbe {mn}, {rn}"), move |e| {
                    e.movbe_mr(mem, r)
                }));
            }
        }
    }
}

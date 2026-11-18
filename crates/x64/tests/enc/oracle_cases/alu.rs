//! `add/or/adc/sbb/and/sub/xor/cmp`, `test`, `neg/not/inc/dec`.

use super::*;

type Rr = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;
type Ri = fn(&mut Emitter, Gp, i64) -> Result<(), EncodeError>;
type Rm = fn(&mut Emitter, Gp, Mem) -> Result<(), EncodeError>;
type Mr = fn(&mut Emitter, Mem, Gp) -> Result<(), EncodeError>;
type Mi = fn(&mut Emitter, Mem, i64) -> Result<(), EncodeError>;
type R1 = fn(&mut Emitter, Gp) -> Result<(), EncodeError>;
type M1 = fn(&mut Emitter, Mem) -> Result<(), EncodeError>;

macro_rules! arith {
    ($($n:literal: $rr:ident $ri:ident $rm:ident $mr:ident $mi:ident;)*) => {
        &[$(($n, Emitter::$rr as Rr, Emitter::$ri as Ri, Emitter::$rm as Rm,
             Emitter::$mr as Mr, Emitter::$mi as Mi)),*]
    };
}

const ARITH: &[(&str, Rr, Ri, Rm, Mr, Mi)] = arith! {
    "add": add_rr add_ri add_rm add_mr add_mi;
    "or": or_rr or_ri or_rm or_mr or_mi;
    "adc": adc_rr adc_ri adc_rm adc_mr adc_mi;
    "sbb": sbb_rr sbb_ri sbb_rm sbb_mr sbb_mi;
    "and": and_rr and_ri and_rm and_mr and_mi;
    "sub": sub_rr sub_ri sub_rm sub_mr sub_mi;
    "xor": xor_rr xor_ri xor_rm xor_mr xor_mi;
    "cmp": cmp_rr cmp_ri cmp_rm cmp_mr cmp_mi;
};

pub fn cases(out: &mut Vec<OCase>) {
    for &(m, rr, ri, rm, mr, mi) in ARITH {
        for size in [1u8, 2, 4, 8] {
            for (dn, d) in gps(size) {
                for (sn, s) in gps_few(size) {
                    out.push(case(format!("{m} {dn}, {sn}"), move |e| rr(e, d, s)));
                }
                for imm in IMMS {
                    out.push(case(format!("{m} {dn}, {imm}"), move |e| ri(e, d, imm)));
                }
            }
            for (rn, r) in gps_few(size) {
                for (mn, mem) in mems(size) {
                    out.push(case(format!("{m} {rn}, {mn}"), move |e| rm(e, r, mem)));
                    out.push(case(format!("{m} {mn}, {rn}"), move |e| mr(e, mem, r)));
                }
            }
            for (mn, mem) in mems(size).into_iter().step_by(3) {
                for imm in IMMS {
                    out.push(case(format!("{m} {mn}, {imm}"), move |e| mi(e, mem, imm)));
                }
            }
        }
        // Unsized memory with an immediate: ambiguous operand size.
        out.push(case(format!("{m} [rax], 1"), move |e| {
            mi(e, ptr(RAX, 0), 1)
        }));
        // Mismatched register sizes.
        out.push(case(format!("{m} rax, ecx"), move |e| rr(e, RAX, ECX)));
        out.push(case(format!("{m} al, cx"), move |e| rr(e, AL, CX)));
        // High-byte registers with REX-requiring operands.
        out.push(case(format!("{m} ah, r9b"), move |e| rr(e, AH, R9B)));
        out.push(case(format!("{m} r9b, ah"), move |e| rr(e, R9B, AH)));
        out.push(case(format!("{m} ah, spl"), move |e| rr(e, AH, SPL)));
        out.push(case(format!("{m} ah, byte ptr [r8]"), move |e| {
            rm(e, AH, byte_ptr(R8, 0))
        }));
        out.push(case(format!("{m} byte ptr [rax+r9], ch"), move |e| {
            mr(e, Mem::base_index(RAX, R9, 0, 0, 1), CH)
        }));
    }

    type Test2 = fn(&mut Emitter, Gp, Gp) -> Result<(), EncodeError>;
    let test_rr: Test2 = Emitter::test_rr;
    for size in [1u8, 2, 4, 8] {
        for (dn, d) in gps(size) {
            for (sn, s) in gps_few(size) {
                out.push(case(format!("test {dn}, {sn}"), move |e| test_rr(e, d, s)));
            }
            for imm in IMMS {
                out.push(case(format!("test {dn}, {imm}"), move |e| {
                    e.test_ri(d, imm)
                }));
            }
        }
        for (rn, r) in gps_few(size) {
            for (mn, mem) in mems(size).into_iter().step_by(2) {
                out.push(case(format!("test {mn}, {rn}"), move |e| e.test_mr(mem, r)));
            }
        }
        for (mn, mem) in mems(size).into_iter().step_by(3) {
            for imm in IMMS {
                out.push(case(format!("test {mn}, {imm}"), move |e| {
                    e.test_mi(mem, imm)
                }));
            }
        }
    }
    out.push(case("test [rax], 1", |e| e.test_mi(ptr(RAX, 0), 1)));
    out.push(case("test rax, ecx", |e| e.test_rr(RAX, ECX)));
    out.push(case("test ah, r9b", |e| e.test_rr(AH, R9B)));

    let unary: &[(&str, R1, M1)] = &[
        ("neg", Emitter::neg_r, Emitter::neg_m),
        ("not", Emitter::not_r, Emitter::not_m),
        ("inc", Emitter::inc_r, Emitter::inc_m),
        ("dec", Emitter::dec_r, Emitter::dec_m),
    ];
    for &(m, r1, m1) in unary {
        for size in [1u8, 2, 4, 8] {
            for (rn, r) in gps(size) {
                out.push(case(format!("{m} {rn}"), move |e| r1(e, r)));
            }
            for (mn, mem) in mems(size) {
                out.push(case(format!("{m} {mn}"), move |e| m1(e, mem)));
            }
        }
        out.push(case(format!("{m} [rax]"), move |e| m1(e, ptr(RAX, 0))));
    }
}

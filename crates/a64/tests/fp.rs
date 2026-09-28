use arinsal_a64::enc::{Cond, Emitter, Gpr, VecReg};

fn fixture() -> Vec<u32> {
    include_str!("fixtures/fp.words")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|word| u32::from_str_radix(word, 16).expect("fixture word"))
        .collect()
}

#[test]
fn clang_assembled_fp_and_d_memory_golden_words() {
    let d = |n| VecReg(n);
    let x = |n| Gpr::x(n);
    let w = |n| Gpr::w(n);
    let mut e = Emitter::new();
    e.fmov_d(d(0), d(1)).unwrap();
    e.fmov_d_from_x(d(2), x(3)).unwrap();
    e.fmov_x_from_d(x(4), d(5)).unwrap();
    e.fmov_d_imm(d(6), 1.0).unwrap();
    e.fabs(d(7), d(8)).unwrap();
    e.fneg(d(9), d(10)).unwrap();
    e.fadd(d(11), d(12), d(13)).unwrap();
    e.fsub(d(14), d(15), d(16)).unwrap();
    e.fmul(d(17), d(18), d(19)).unwrap();
    e.fdiv(d(20), d(21), d(22)).unwrap();
    e.fsqrt(d(23), d(24)).unwrap();
    e.fcmp(d(25), d(26)).unwrap();
    e.fcmpe(d(27), d(28)).unwrap();
    e.scvtf_d_x(d(29), x(30)).unwrap();
    e.fcvtzs_x_from_d(x(0), d(1)).unwrap();
    e.fcvtzs_w_from_d(w(2), d(3)).unwrap();
    e.fcvtms_x_from_d(x(4), d(5)).unwrap();
    e.fcvtms_w_from_d(w(6), d(7)).unwrap();
    e.fcvtps_x_from_d(x(8), d(9)).unwrap();
    e.fcvtps_w_from_d(w(10), d(11)).unwrap();
    e.frintz(d(12), d(13)).unwrap();
    e.frintm(d(14), d(15)).unwrap();
    e.frintp(d(16), d(17)).unwrap();
    e.fccmp(d(18), d(19), 7, Cond::Ge).unwrap();
    e.fcsel(d(20), d(21), d(22), Cond::Lt).unwrap();
    e.ldr_d_uoff(d(0), x(1), 24).unwrap();
    e.str_d_uoff(d(2), x(3), 32).unwrap();
    e.ldur_d(d(4), x(5), -8).unwrap();
    e.stur_d(d(6), x(7), 16).unwrap();
    e.ldr_d_pre(d(8), x(9), 8).unwrap();
    e.str_d_pre(d(10), x(11), -16).unwrap();
    e.ldr_d_post(d(12), x(13), 24).unwrap();
    e.str_d_post(d(14), x(15), -8).unwrap();
    e.ldr_d_regoff(d(16), x(17), x(18), false).unwrap();
    e.str_d_regoff(d(19), x(20), x(21), true).unwrap();
    e.ldp_d(d(22), d(23), x(24), 16).unwrap();
    e.stp_d(d(25), d(26), x(27), -16).unwrap();
    e.ldp_d_pre(d(0), d(1), x(2), -16).unwrap();
    e.stp_d_pre(d(3), d(4), x(5), 16).unwrap();
    e.ldp_d_post(d(6), d(7), x(8), 16).unwrap();
    e.stp_d_post(d(9), d(10), x(11), -16).unwrap();
    e.ldr_d_literal(d(11), 2).unwrap();
    e.cnt_8b(d(12), d(13)).unwrap();
    e.addv_8b(d(14), d(15)).unwrap();
    e.movi_16b(d(16), 0x5a).unwrap();
    e.ldr_q_uoff(d(0), x(1), 16).unwrap();
    e.str_q_uoff(d(2), x(3), 32).unwrap();
    e.ldur_q(d(4), x(5), -16).unwrap();
    e.stur_q(d(6), x(7), 16).unwrap();
    e.ldr_q_pre(d(8), x(9), 16).unwrap();
    e.str_q_pre(d(10), x(11), -16).unwrap();
    e.ldr_q_post(d(12), x(13), 24).unwrap();
    e.str_q_post(d(14), x(15), -8).unwrap();
    e.ldp_q(d(16), d(17), x(18), 32).unwrap();
    e.stp_q(d(19), d(20), x(21), -32).unwrap();
    e.ldp_q_pre(d(22), d(23), x(24), -32).unwrap();
    e.stp_q_pre(d(25), d(26), x(27), 32).unwrap();
    e.ldp_q_post(d(28), d(29), x(0), 32).unwrap();
    e.stp_q_post(d(30), d(31), x(1), -32).unwrap();
    assert_eq!(e.words, fixture());
}

#[test]
fn every_fp_simd_mnemonic_found_in_beamasm_sources_is_encodable() {
    // Inventory from OTP's ARM64 assembler instruction sources.
    // The source uses ldr/str/ldp/stp for GP and SIMD registers, so exercise SIMD forms here.
    let source_mnemonics = [
        "fabs", "fcmp", "fcmpe", "fmov", "fneg", "scvtf", "cnt", "addv", "movi", "ldr", "str",
        "ldp", "stp",
    ];
    let mut e = Emitter::new();
    let d = VecReg(0);
    let x = Gpr::x(0);
    e.fabs(d, d).unwrap();
    e.fcmp(d, d).unwrap();
    e.fcmpe(d, d).unwrap();
    e.fmov_d(d, d).unwrap();
    e.fmov_d_from_x(d, x).unwrap();
    e.fmov_x_from_d(x, d).unwrap();
    e.fmov_d_imm8(d, 0x70).unwrap();
    e.fneg(d, d).unwrap();
    e.scvtf_d_x(d, x).unwrap();
    e.cnt_8b(d, d).unwrap();
    e.addv_8b(d, d).unwrap();
    e.movi_16b(d, 1).unwrap();
    e.ldr_d_uoff(d, x, 0).unwrap();
    e.str_d_uoff(d, x, 0).unwrap();
    e.ldp_q(d, VecReg(1), x, 0).unwrap();
    e.stp_q(d, VecReg(1), x, 0).unwrap();
    assert_eq!(source_mnemonics.len(), 13);
    assert_eq!(e.len(), 16);
}

use arinsal_a64::enc::{Cond, Emitter, Extend, Extended, Gpr, Shift, Shifted, VecReg};

fn fixture() -> Vec<u32> {
    include_str!("fixtures/enc.words")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|word| u32::from_str_radix(word, 16).expect("fixture word"))
        .collect()
}

#[test]
fn clang_assembled_golden_words() {
    let mut e = Emitter::new();
    e.add_imm(Gpr::x(0), Gpr::x(1), 4095, false).unwrap();
    e.adds_imm(Gpr::w(2), Gpr::w(3), 7, false).unwrap();
    e.sub_imm(Gpr::x(4), Gpr::x(5), 1, true).unwrap();
    e.subs_reg(Gpr::x(6), Gpr::x(7), Gpr::x(8), Shift::Lsr, 3)
        .unwrap();
    e.adc(Gpr::x(9), Gpr::x(10), Gpr::x(11)).unwrap();
    e.and_imm(Gpr::x(12), Gpr::x(13), 255).unwrap();
    e.orr_reg(
        Gpr::x(14),
        Gpr::x(15),
        Shifted {
            reg: Gpr::x(16),
            shift: Shift::Lsl,
            amount: 0,
        },
    )
    .unwrap();
    e.bfi(Gpr::x(17), Gpr::x(18), 4, 8).unwrap();
    e.movz(Gpr::x(19), 0xabcd, 32).unwrap();
    e.ldr_uoff(Gpr::x(20), Gpr::x(21), 32760).unwrap();
    e.str_uoff(Gpr::w(22), Gpr::sp(), 4092).unwrap();
    e.ldur(Gpr::x(23), Gpr::x(24), -256).unwrap();
    e.stur(Gpr::w(25), Gpr::x(26), 255).unwrap();
    e.ldp_pre(Gpr::x(27), Gpr::x(28), Gpr::sp(), -16).unwrap();
    e.stp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16).unwrap();
    e.ldr_regoff(Gpr::x(0), Gpr::x(1), Gpr::x(2), 3).unwrap();
    e.b(4).unwrap();
    e.bl(-2).unwrap();
    e.b_cond(Cond::Eq, 3).unwrap();
    e.cbnz(Gpr::w(4), -4).unwrap();
    e.tbz(Gpr::x(5), 42, 7).unwrap();
    e.br(Gpr::x(6)).unwrap();
    e.adr(Gpr::x(7), 12).unwrap();
    e.csel(Gpr::x(8), Gpr::x(9), Gpr::x(10), Cond::Ge).unwrap();
    e.mul(Gpr::x(11), Gpr::x(12), Gpr::x(13)).unwrap();
    e.sdiv(Gpr::x(14), Gpr::x(15), Gpr::x(16)).unwrap();
    e.rev64(Gpr::x(17), Gpr::x(18)).unwrap();
    e.nop();
    e.udf(0xbeef);
    e.ldrb_uoff(Gpr::w(0), Gpr::x(1), 4095).unwrap();
    e.strh_uoff(Gpr::w(2), Gpr::x(3), 8190).unwrap();
    e.ldurb(Gpr::w(4), Gpr::x(5), -1).unwrap();
    e.sturh(Gpr::w(6), Gpr::x(7), 2).unwrap();
    e.ldaxr(Gpr::x(8), Gpr::x(9)).unwrap();
    e.stlxr(Gpr::w(10), Gpr::x(11), Gpr::x(12)).unwrap();
    e.ldaddal(Gpr::x(13), Gpr::x(14), Gpr::x(15)).unwrap();
    e.ldr_d_uoff(VecReg(16), Gpr::x(17), 32760).unwrap();
    e.str_d_uoff(VecReg(18), Gpr::x(19), 8).unwrap();
    e.fmov_d(VecReg(20), VecReg(21)).unwrap();
    e.fabs(VecReg(22), VecReg(23)).unwrap();
    e.fneg(VecReg(24), VecReg(25)).unwrap();
    e.fcmp(VecReg(26), VecReg(27)).unwrap();
    e.fcmpe(VecReg(28), VecReg(29)).unwrap();
    e.scvtf_d_x(VecReg(30), Gpr::x(0)).unwrap();
    e.cnt_8b(VecReg(1), VecReg(2)).unwrap();
    e.addv_8b(VecReg(3), VecReg(4)).unwrap();
    e.movi_16b(VecReg(0), 255).unwrap();
    e.movi_8b(VecReg(1), 1).unwrap();
    e.lsl_reg(Gpr::x(2), Gpr::x(3), Gpr::x(4)).unwrap();
    e.lsr_reg(Gpr::w(5), Gpr::w(6), Gpr::w(7)).unwrap();
    e.asr_reg(Gpr::x(8), Gpr::x(9), Gpr::x(10)).unwrap();
    e.ror_reg(Gpr::x(11), Gpr::x(12), Gpr::x(13)).unwrap();
    e.ror_imm(Gpr::x(14), Gpr::x(15), 7).unwrap();
    e.ccmp_imm(Gpr::x(1), 3, 4, Cond::Eq).unwrap();
    e.ccmn_imm(Gpr::w(2), 5, 6, Cond::Ne).unwrap();
    e.fmov_d_from_x(VecReg(0), Gpr::x(1)).unwrap();
    e.fmov_x_from_d(Gpr::x(2), VecReg(3)).unwrap();
    e.mov_const(Gpr::x(0), u64::MAX).unwrap();
    e.mov_const(Gpr::x(1), 0x1234_5678_9abc_def0).unwrap();
    e.mov_const(Gpr::w(2), u32::MAX as u64).unwrap();
    e.mov_const(Gpr::x(3), 0).unwrap();
    e.adds_reg(Gpr::x(0), Gpr::x(1), Gpr::x(2), Shift::Lsl, 1)
        .unwrap();
    e.sub_reg(Gpr::w(3), Gpr::w(4), Gpr::w(5), Shift::Asr, 2)
        .unwrap();
    e.add_ext(
        Gpr::x(6),
        Gpr::x(7),
        Extended {
            reg: Gpr::w(8),
            extend: Extend::Uxtw,
            amount: 3,
        },
    )
    .unwrap();
    e.sub_ext(
        Gpr::x(9),
        Gpr::x(10),
        Extended {
            reg: Gpr::x(11),
            extend: Extend::Sxtx,
            amount: 0,
        },
    )
    .unwrap();
    e.cmn_imm(Gpr::x(12), 255, false).unwrap();
    e.cmp_reg(Gpr::w(13), Gpr::w(14), Shift::Lsl, 2).unwrap();
    e.tst_imm(Gpr::x(15), 255).unwrap();
    e.ccmp_reg(Gpr::x(16), Gpr::x(17), 5, Cond::Ne).unwrap();
    e.ccmn_reg(Gpr::x(18), Gpr::x(19), 6, Cond::Eq).unwrap();
    e.neg(Gpr::x(20), Gpr::x(21)).unwrap();
    e.negs(Gpr::w(22), Gpr::w(23)).unwrap();
    e.ngc(Gpr::x(24), Gpr::x(25)).unwrap();
    e.ands_reg(
        Gpr::x(26),
        Gpr::x(27),
        Shifted {
            reg: Gpr::x(28),
            shift: Shift::Ror,
            amount: 4,
        },
    )
    .unwrap();
    e.eor_imm(Gpr::w(0), Gpr::w(1), 0xff00_ff00).unwrap();
    e.lsr_imm(Gpr::x(2), Gpr::x(3), 63).unwrap();
    e.ubfx(Gpr::x(4), Gpr::x(5), 8, 16).unwrap();
    e.ubfiz(Gpr::x(6), Gpr::x(7), 4, 8).unwrap();
    e.sbfx(Gpr::x(8), Gpr::x(9), 3, 12).unwrap();
    e.bfxil(Gpr::x(10), Gpr::x(11), 5, 7).unwrap();
    e.smulh(Gpr::x(12), Gpr::x(13), Gpr::x(14)).unwrap();
    e.madd(Gpr::x(15), Gpr::x(16), Gpr::x(17), Gpr::x(18), false)
        .unwrap();
    e.msub(Gpr::w(19), Gpr::w(20), Gpr::w(21), Gpr::w(22))
        .unwrap();
    e.udiv(Gpr::x(23), Gpr::x(24), Gpr::x(25)).unwrap();
    e.rev16(Gpr::w(26), Gpr::w(27)).unwrap();
    e.rev32(Gpr::x(28), Gpr::x(29)).unwrap();
    e.cls(Gpr::w(30), Gpr::w(0)).unwrap();
    e.cset(Gpr::x(1), Cond::Eq).unwrap();
    e.csetm(Gpr::w(2), Cond::Hi).unwrap();
    e.cinc(Gpr::x(3), Gpr::x(4), Cond::Ne).unwrap();
    e.csinv(Gpr::x(5), Gpr::x(6), Gpr::x(7), Cond::Lt).unwrap();
    e.cbz(Gpr::x(8), 3).unwrap();
    e.tbnz(Gpr::w(9), 31, -2).unwrap();
    e.blr(Gpr::x(10)).unwrap();
    e.ret(Gpr::x(30)).unwrap();
    e.ldr_uoff(Gpr::w(11), Gpr::x(12), 4092).unwrap();
    e.stur(Gpr::x(13), Gpr::x(14), -8).unwrap();
    e.ldp(Gpr::w(15), Gpr::w(16), Gpr::x(17), 12).unwrap();
    e.stp(Gpr::x(18), Gpr::x(19), Gpr::sp(), -16).unwrap();
    e.ldr_literal(Gpr::x(0), 2).unwrap();
    e.ldr_post(Gpr::x(1), Gpr::x(2), 8).unwrap();
    e.str_post(Gpr::x(3), Gpr::x(4), -8).unwrap();
    e.ldr_pre(Gpr::x(5), Gpr::x(6), -8).unwrap();
    e.str_pre(Gpr::w(7), Gpr::x(8), 4).unwrap();
    e.sturb(Gpr::w(9), Gpr::x(10), -3).unwrap();
    e.ldurh(Gpr::w(11), Gpr::x(12), 2).unwrap();
    e.adr(Gpr::x(13), -4).unwrap();
    e.embed_uint32(0x1234_5678);
    e.embed_uint64(0x1234_5678_9abc_def0);
    e.movi_2d(VecReg(0), u64::MAX).unwrap();
    e.movi_2d(VecReg(31), 0).unwrap();
    e.movi_d(VecReg(31), 0).unwrap();
    e.add_reg(Gpr::x(0), Gpr::x(1), Gpr::x(2), Shift::Lsl, 0)
        .unwrap();
    e.subs_imm(Gpr::x(3), Gpr::x(4), 5, false).unwrap();
    e.and_reg(
        Gpr::x(5),
        Gpr::x(6),
        Shifted {
            reg: Gpr::x(7),
            shift: Shift::Lsl,
            amount: 0,
        },
    )
    .unwrap();
    e.orr_imm(Gpr::x(8), Gpr::x(9), 255).unwrap();
    e.eor_reg(
        Gpr::x(10),
        Gpr::x(11),
        Shifted {
            reg: Gpr::x(12),
            shift: Shift::Lsl,
            amount: 0,
        },
    )
    .unwrap();
    e.tst_reg(Gpr::x(13), Gpr::x(14), Shift::Lsl, 0).unwrap();
    e.cmp_imm(Gpr::x(15), 3, false).unwrap();
    e.strb_uoff(Gpr::w(16), Gpr::x(17), 4095).unwrap();
    e.ldrh_uoff(Gpr::w(18), Gpr::x(19), 8190).unwrap();
    e.lsl_imm(Gpr::x(20), Gpr::x(21), 0).unwrap();
    e.asr_imm(Gpr::w(22), Gpr::w(23), 31).unwrap();
    e.extr(Gpr::x(24), Gpr::x(25), Gpr::x(26), 7).unwrap();
    assert_eq!(e.words, fixture());
}

#[test]
fn rejects_out_of_range_and_unencodable_operands() {
    let mut e = Emitter::new();
    assert!(e.add_imm(Gpr::x(0), Gpr::x(1), 4096, false).is_err());
    assert!(e.ldr_uoff(Gpr::x(0), Gpr::x(1), 7).is_err());
    assert!(e.ldur(Gpr::x(0), Gpr::x(1), -257).is_err());
    assert!(e.b_cond(Cond::Eq, 1 << 18).is_err());
    assert!(e.and_imm(Gpr::x(0), Gpr::x(1), 0x1234).is_err());
    assert!(
        e.add_ext(
            Gpr::x(0),
            Gpr::x(1),
            Extended {
                reg: Gpr::w(2),
                extend: Extend::Uxtw,
                amount: 5
            }
        )
        .is_err()
    );
    assert!(
        e.add_reg(Gpr::sp(), Gpr::x(1), Gpr::x(2), Shift::Lsl, 0)
            .is_err()
    );
    assert!(e.str_uoff(Gpr::sp(), Gpr::x(1), 0).is_err());
    assert!(e.b(i32::MIN).is_err());
    assert!(e.stp(Gpr::x(0), Gpr::x(1), Gpr::sp(), 7).is_err());
}

#[test]
fn stack_pointer_forms_and_alignment_directive() {
    let mut e = Emitter::new();
    e.mov_reg(Gpr::sp(), Gpr::x(0)).unwrap();
    e.nop();
    e.align(4).unwrap();
    assert_eq!(
        e.words,
        [0x9100_001f, 0xd503_201f, 0xd503_201f, 0xd503_201f]
    );
    e.embed_label(0x1234_5678_9abc_def0);
    assert_eq!(&e.words[4..], &[0x9abc_def0, 0x1234_5678]);
}

#[test]
fn logical_immediate_reports_encodability() {
    use arinsal_a64::enc::is_logical_immediate;
    assert!(is_logical_immediate(0x00ff_00ff_00ff_00ff, 64));
    assert!(is_logical_immediate(0x8000_0000, 32));
    assert!(!is_logical_immediate(u64::MAX, 64));
    assert!(!is_logical_immediate(0x1234, 64));
}
